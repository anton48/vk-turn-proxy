package main

import (
	"context"
	"log"
	"net"
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
//     and talking, just not on this connection — and goes EARLIER than 150 s;
//   - a group the client has SUPERSEDED (it says so with a sentinel on the
//     connections of its new group after a network switch — see
//     isGroupSupersede) goes at the next tick, so no repeat is ever sent into
//     released allocations. 🚫 A whole group that is merely silent is NOT kept
//     longer than today on the theory that its client sleeps: a group left
//     behind by a switch is silent in exactly the same way, and a relayed
//     address the relay has recycled for another allocation would deliver the
//     repeat to a stranger's session.
//
// THE NUMBERS are the user's (2026-09-22): 45 / 60 / 90 s. Vars, not consts, so
// that main() can set them from flags and a test can shrink them — written once
// before any connection exists, read-only afterwards (the reaper's contract).
const (
	defaultKeepaliveAfter        = 45 * time.Second // silence before the first repeat
	defaultKeepaliveEvery        = 60 * time.Second // between repeats while the silence lasts; 0 = no repeats at all
	defaultReapZombieAfter       = 90 * time.Second // a member silent this long beside a heard neighbour is a zombie
	defaultZombieNeighbourWithin = 60 * time.Second // ...if the group heard another member this recently
)

var (
	keepaliveAfter        = defaultKeepaliveAfter
	keepaliveEvery        = defaultKeepaliveEvery
	reapZombieAfter       = defaultReapZombieAfter
	zombieNeighbourWithin = defaultZombieNeighbourWithin
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
// thing the keepalive is allowed to send. Written by the inbound pump, read by
// the clockwork; a fresh copy per set, so a reader never sees a buffer being
// reused for the next read.
type lastEcho struct {
	p atomic.Pointer[[]byte]
}

func (e *lastEcho) set(b []byte) {
	cp := append([]byte(nil), b...)
	e.p.Store(&cp)
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
	after, every, zombie, neighbour, idle time.Duration

	lastRepeat time.Time // zero until the first repeat
}

func newClockwork() *clockwork {
	return &clockwork{
		after: keepaliveAfter, every: keepaliveEvery,
		zombie: reapZombieAfter, neighbour: zombieNeighbourWithin,
		idle: groupIdleTimeout,
	}
}

// clockworkInput is what one tick reads: when this connection was last heard,
// when its group last heard ANY member (zero when ungrouped), whether the group
// was superseded, and whether an echo exists to repeat.
type clockworkInput struct {
	now, lastInbound, groupLastInbound time.Time
	grouped, superseded, haveEcho      bool
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
		case idle > c.zombie && !in.groupLastInbound.IsZero() && in.now.Sub(in.groupLastInbound) < c.neighbour:
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
	c.lastRepeat = in.now
	return true, reapNone
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
				if ns := h.lastInbound.Load(); ns != 0 {
					in.groupLastInbound = time.Unix(0, ns)
				}
				in.superseded = h.superseded.Load()
			}
			repeat, reap := cw.step(in)
			if reap != reapNone {
				idle := now.Sub(in.lastInbound).Round(time.Second)
				switch reap {
				case reapZombie:
					log.Printf("conn %d: no inbound for %s while its group heard another "+
						"connection %s ago — a zombie, reaping", st.id, idle,
						now.Sub(in.groupLastInbound).Round(time.Second))
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
			// The bytes the client has already accepted once, and nothing else.
			_ = conn.SetWriteDeadline(now.Add(5 * time.Second))
			if _, err := conn.Write(echo.get()); err != nil {
				keepaliveWriteFails.Add(1)
				log.Printf("conn %d: keepalive write failed: %s", st.id, err)
				cancel()
				return
			}
			st.keepalives.Add(1)
			keepaliveRepeats.Add(1)
		}
	}
}
