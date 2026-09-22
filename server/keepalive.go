package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The server-side keepalive, and the reaper that knows.
//
// WHY. Over a UDP relay leg a sleeping phone hears nothing from this server:
// WireGuard sends nothing on an idle tunnel, the VK relay sends nothing over
// UDP (over TCP it probes every 60 s, and that probe is what keeps a TCP phone
// waking once a minute), so the phone sleeps iOS's whole cycle — up to ten
// minutes — while the home NAT's UDP state (300 s), the relay's permission
// (300 s, refreshed only by an awake client) and this server's own idle reaper
// (150 s) all run out behind it. Measured on the client's side: 599 server-
// reaped sessions in one night, every one replaced at the next wake. An
// inbound datagram wakes the phone (a router capture, 2026-09-20), so a packet
// from here once a minute is what turns a UDP night into a TCP one.
//
// THE FORM. A byte-for-byte REPEAT of the last probe echo this connection sent.
// Every released client already understands it: it is a pong it has seen, and
// its pong handler stamps the time of ANY pong — the periodic zombie detector's
// clock — while the sequence mark moves forward only (client build 422+).
// 🚫 Never an invented sequence number: a client that predates 422 stores the
// pong's seq unconditionally, and a made-up or stale seq overtaking a fresh
// pong would move its mark BACK and get a healthy connection killed. The
// repeat carries nothing the client has not already accepted once.
//
// WHEN. Only on a connection that has been SILENT — nothing read from the
// client — for keepaliveAfter, then every keepaliveEvery of continued silence,
// measured by the same lastInbound the reaper reads. A connection that has just
// spoken gets no repeat, which is what keeps a stale repeat from racing the
// fresh pong the client's own ping is about to earn. And never before the
// connection has echoed a probe: a client that does not probe gets nothing.
//
// COVERAGE. Every connection. One packet a minute on ONE connection is a single
// point of failure — six freezes of 94-142 s in a night that had exactly that.
//
// THE REAPER, WITH IT. Today's rule — silent for groupIdleTimeout, reap — stays
// as the backstop: with repeats going out every minute, 150 s of silence means
// three of them did not wake the client, so its mapping, its permission or its
// network is gone, or it has switched networks and left this group behind.
// Two things it could not tell before, it can now:
//   - a member silent for reapZombieAfter while a NEIGHBOUR in the same group
//     was heard within zombieNeighbourWithin is a zombie — its client is awake
//     and talking, just not on this connection — and goes EARLIER than 150 s.
//     🚫 Not at the moment the group WAKES: after a sleep every member's silence
//     is the sleep's length, and the first pings of the wake's burst make the
//     neighbour condition true while the rest are still in flight — five
//     healthy connections were reaped that way a second after a 104-s sleep
//     (2026-09-22 evening). So the group keeps the moment it woke (awakeSince:
//     the inbound that ended a gap of groupSleepGap — the silence that earns a
//     repeat, well above the client's 30-s ping interval, so that an awake
//     group's ordinary gaps never count), and a zombie is reaped only once its
//     group has been awake for zombieAwakeFor — a ping interval plus a tick,
//     the time every healthy member needs to have spoken. The margin between
//     reapZombieAfter and zombieNeighbourWithin is the ping interval, which is
//     what keeps a member from looking like a zombie while the whole group
//     sleeps. The two stamps are ONE value (groupClock), written and read
//     whole: a reader that saw the fresh neighbour beside the old wake would
//     reap the late member all the same. ⚖️ The grace is the ZOMBIE rule's
//     alone: the backstop counts a member's own silence and takes it at 150 s
//     whatever its group did a moment ago — a wake at the 140th second of a
//     member's silence does not buy it 45 more (a kept policy, stated);
//   - a group the client has SUPERSEDED (it says so with a sentinel on the
//     connections of its new group after a network switch — see
//     isGroupSupersede) goes at the next tick, so no repeat is ever sent into
//     released allocations. 🚫 A whole group that is merely silent is NOT kept
//     longer than today on the theory that its client sleeps: a group left
//     behind by a switch is silent in exactly the same way, and a relayed
//     address the relay has recycled for another allocation would deliver the
//     repeat to a stranger's session.
//
// THE NUMBERS are the user's (2026-09-22): 45 / 60 / 90 s, and the wake's grace
// of 45 s from the evening's field result. Vars, not consts, so that main() can
// set them from flags and a test can shrink them — written once before any
// connection exists, read-only afterwards (the reaper's contract).
const (
	defaultKeepaliveAfter        = 45 * time.Second // silence before the first repeat
	defaultKeepaliveEvery        = 60 * time.Second // between repeats while the silence lasts; 0 = no repeats at all
	defaultReapZombieAfter       = 90 * time.Second // a member silent this long beside a heard neighbour is a zombie
	defaultZombieNeighbourWithin = 60 * time.Second // ...if the group heard another member this recently
	defaultZombieAwakeFor        = 45 * time.Second // ...and only once the group has been awake this long: a ping interval + a tick; 0 = the rule without the grace
	defaultGroupSleepGap         = 45 * time.Second // a gap in the group's inbound this long is a sleep (the silence that earns a repeat, well above the 30-s ping interval); the inbound that ends it is the wake
)

var (
	keepaliveAfter        = defaultKeepaliveAfter
	keepaliveEvery        = defaultKeepaliveEvery
	reapZombieAfter       = defaultReapZombieAfter
	zombieNeighbourWithin = defaultZombieNeighbourWithin
	zombieAwakeFor        = defaultZombieAwakeFor
	groupSleepGap         = defaultGroupSleepGap
)

// groupSupersedeMagic is the sentinel a client sends on the connections of its
// NEW group, right after their hello, naming the group it has just left:
// 0xff 'S' 'U' 'P' + the 16-byte OLD session id. Same construction and the same
// length as the hello, for the same reasons: 0xff is outside WireGuard's message
// types, so a server that predates this forwards it to WireGuard, which drops
// it as malformed — one dropped 20-byte packet per connection per switch.
var groupSupersedeMagic = []byte{0xff, 'S', 'U', 'P'}

// isGroupSupersede reports whether buf is a supersede sentinel and returns the
// group it names. Exact length, like the hello: nothing else may be mistaken
// for it, or a WireGuard packet would be swallowed.
func isGroupSupersede(buf []byte) (groupKey, bool) {
	var k groupKey
	if len(buf) != groupHelloLen {
		return k, false
	}
	for i, b := range groupSupersedeMagic {
		if buf[i] != b {
			return k, false
		}
	}
	copy(k[:], buf[4:groupHelloLen])
	return k, true
}

// lastEcho keeps the bytes of the last probe this connection echoed — the only
// thing the keepalive is allowed to send — and ORDERS the echoes and the
// repeats on the wire. The order is load-bearing for a client that predates
// build 422: its pong handler stores the seq it sees unconditionally, so a
// repeat of seq 1 landing AFTER the fresh echo of seq 2 moves its mark back
// and its probe misses the answer it had earned. The inbound pump's read stamps
// lastInbound BEFORE its echo takes this lock; the repeat re-reads that stamp
// under the same lock right before it writes and sends nothing if the client
// has spoken since the tick decided. So a repeat is always written BEFORE any
// echo of a later ping, never behind it. A fresh copy per set, so a reader
// never sees a buffer being reused for the next read.
type lastEcho struct {
	mu sync.Mutex // held across every echo write and every repeat's check-and-write
	p  atomic.Pointer[[]byte]
}

// echo writes a probe back to the client and keeps it as the last echo. The
// caller has stamped lastInbound for this very read already.
func (e *lastEcho) echo(conn net.Conn, pkt []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	cp := append([]byte(nil), pkt...)
	e.p.Store(&cp)
	return nil
}

// repeat writes the last echo again — unless the client has spoken since the
// clockwork decided to (a read newer than `after` ago), in which case nothing
// is written: the fresh echo that read earned goes out instead, and a repeat
// behind it would have been the stale seq the old clients cannot take.
// Returns whether a repeat was written.
func (e *lastEcho) repeat(conn net.Conn, lastInbound *atomic.Int64, after time.Duration) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if time.Since(time.Unix(0, lastInbound.Load())) < after {
		return false, nil
	}
	b := e.get()
	if b == nil {
		return false, nil
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(b); err != nil {
		return false, err
	}
	return true, nil
}

// get returns nil until a probe has been echoed.
func (e *lastEcho) get() []byte {
	if p := e.p.Load(); p != nil {
		return *p
	}
	return nil
}

// reapReason says WHICH rule ended a connection; the log line and the counters
// name it, because a reaper that only says "reaped" cannot be checked against
// a client log afterwards.
type reapReason int

const (
	reapNone       reapReason = iota
	reapIdle                  // silent for groupIdleTimeout — the backstop, as before
	reapZombie                // silent beside a neighbour the group heard from
	reapSuperseded            // the client said it left this group
)

func (r reapReason) String() string {
	switch r {
	case reapIdle:
		return "idle"
	case reapZombie:
		return "zombie"
	case reapSuperseded:
		return "superseded"
	}
	return "none"
}

// clockwork is ONE connection's timed duties — the keepalive repeat and the
// three reaper rules — as a table over the clocks it reads, with the knobs
// captured at construction so that the rules can be tested without a goroutine.
type clockwork struct {
	after, every, zombie, neighbour, awakeFor, idle time.Duration

	lastRepeat time.Time // zero until the first repeat
}

func newClockwork() *clockwork {
	return &clockwork{
		after: keepaliveAfter, every: keepaliveEvery,
		zombie: reapZombieAfter, neighbour: zombieNeighbourWithin, awakeFor: zombieAwakeFor,
		idle: groupIdleTimeout,
	}
}

// clockworkInput is what one tick reads: when this connection was last heard,
// when its group last heard ANY member and when it last WOKE (both zero when
// ungrouped), whether the group was superseded, and whether an echo exists to
// repeat.
type clockworkInput struct {
	now, lastInbound, groupLastInbound, groupAwakeSince time.Time
	grouped, superseded, haveEcho                       bool
}

// step decides one tick. The reaper's verdict comes first: a connection that is
// being reaped gets no repeat. Then the repeat, which needs an echo to repeat,
// keepaliveEvery > 0, silence of at least keepaliveAfter, and keepaliveEvery
// since the previous repeat.
func (c *clockwork) step(in clockworkInput) (repeat bool, reap reapReason) {
	idle := in.now.Sub(in.lastInbound)
	if in.grouped {
		switch {
		case in.superseded:
			return false, reapSuperseded
		case idle > c.zombie && !in.groupLastInbound.IsZero() && in.now.Sub(in.groupLastInbound) < c.neighbour &&
			c.groupAwake(in):
			return false, reapZombie
		case idle > c.idle:
			return false, reapIdle
		}
	}
	if c.every <= 0 || !in.haveEcho || idle < c.after {
		return false, reapNone
	}
	if !c.lastRepeat.IsZero() && in.now.Sub(c.lastRepeat) < c.every {
		return false, reapNone
	}
	return true, reapNone
}

// groupAwake says whether the group has been awake long enough for a silent
// member to be a zombie rather than a late waker: zombieAwakeFor since the
// inbound that ended the group's last sleep. A zero awake stamp (no sleep on
// record) or a grace of 0 is the rule without it.
func (c *clockwork) groupAwake(in clockworkInput) bool {
	return c.awakeFor <= 0 || in.groupAwakeSince.IsZero() || in.now.Sub(in.groupAwakeSince) >= c.awakeFor
}

// repeated stamps the repeat that was WRITTEN — one the gate held back (the
// client spoke meanwhile) leaves the stamp alone, so the next silence gets
// its first repeat at keepaliveAfter and not a full interval later.
func (c *clockwork) repeated(now time.Time) { c.lastRepeat = now }

// send carries out a repeat the tick decided: the write goes through the
// echo's gate — which holds it back if the client has spoken since — and only
// a repeat that was WRITTEN is stamped. Returns whether one was written.
func (c *clockwork) send(conn net.Conn, lastInbound *atomic.Int64, echo *lastEcho, now time.Time) (bool, error) {
	sent, err := echo.repeat(conn, lastInbound, c.after)
	if err != nil || !sent {
		return false, err
	}
	c.repeated(now)
	return true, nil
}

// The reaper's counters, by reason, and the keepalive's — read by the
// conn-stats dump beside the byte counters.
var (
	keepaliveRepeats    atomic.Int64
	keepaliveWriteFails atomic.Int64
	reapsByReason       [4]atomic.Int64 // indexed by reapReason
)

// runClockwork is the goroutine that ticks a connection's clockwork every
// groupReapEvery: it repeats the last echo into a silence and it reaps by the
// rules above. `cancel` ends the connection; `hubOf` reads the current binding
// (a connection is promoted into its group while this runs).
func runClockwork(ctx context.Context, conn net.Conn, st *connStat, lastInbound *atomic.Int64,
	echo *lastEcho, hubOf func() *downlinkHub, cancel context.CancelFunc) {
	cw := newClockwork()
	t := time.NewTicker(groupReapEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h := hubOf()
			in := clockworkInput{
				now:         now,
				lastInbound: time.Unix(0, lastInbound.Load()),
				grouped:     h != nil,
				haveEcho:    echo.get() != nil,
			}
			if h != nil {
				// The pair from ONE load: a fresh neighbour is never read beside a
				// stale wake (the review of b6e89b5).
				last, awake := h.heardAt()
				if last != 0 {
					in.groupLastInbound = time.Unix(0, last)
				}
				if awake != 0 {
					in.groupAwakeSince = time.Unix(0, awake)
				}
				in.superseded = h.superseded.Load()
			}
			repeat, reap := cw.step(in)
			if reap != reapNone {
				idle := now.Sub(in.lastInbound).Round(time.Second)
				switch reap {
				case reapZombie:
					log.Printf("conn %d: no inbound for %s while its group heard another "+
						"connection %s ago and has been awake for %s — a zombie, reaping", st.id, idle,
						now.Sub(in.groupLastInbound).Round(time.Second),
						now.Sub(in.groupAwakeSince).Round(time.Second))
				case reapSuperseded:
					log.Printf("conn %d: its group was superseded by the client's new group "+
						"(silent %s) — reaping", st.id, idle)
				default:
					log.Printf("conn %d: no inbound for %s, reaping — a silent "+
						"connection in a group still steals downlink", st.id, idle)
				}
				st.reaped.Store(int64(reap))
				reapsByReason[reap].Add(1)
				cancel()
				return
			}
			if !repeat {
				continue
			}
			// The bytes the client has already accepted once, and nothing else —
			// and only if the client is still silent at the moment of the write.
			sent, err := cw.send(conn, lastInbound, echo, now)
			if err != nil {
				keepaliveWriteFails.Add(1)
				log.Printf("conn %d: keepalive write failed: %s", st.id, err)
				cancel()
				return
			}
			if !sent {
				continue
			}
			st.keepalives.Add(1)
			keepaliveRepeats.Add(1)
		}
	}
}
