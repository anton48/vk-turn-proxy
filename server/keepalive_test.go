package main

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// probe builds the client's 12-byte probe: the sentinel + a big-endian seq.
func probe(seq uint64) []byte {
	p := append([]byte(nil), 0xff, 'P', 'N', 'G')
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	return append(p, s[:]...)
}

// supersede builds the sentinel naming the group whose id is 16 × id.
func supersede(id byte) []byte {
	p := append([]byte(nil), 0xff, 'S', 'U', 'P')
	for i := 0; i < groupIDLen; i++ {
		p = append(p, id)
	}
	return p
}

// pump runs pumpBidirectional on c against a throwaway WireGuard side and
// returns a channel closed when the pump has returned, and a stop.
func pump(t *testing.T, c *scriptedConn) (done chan struct{}, stop func()) {
	t.Helper()
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		defer close(done)
		pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false)
	}()
	return done, func() {
		cancel()
		c.Close()
		<-done
		wgSide.Close()
	}
}

func ended(done chan struct{}, within time.Duration) bool {
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// The keepalive's whole reason: a connection that has echoed a probe and then
// falls silent receives that echo again — the same bytes — after keepaliveAfter,
// and again every keepaliveEvery while the silence lasts.
func TestASilentConnectionGetsItsLastEchoRepeated(t *testing.T) {
	c := newScriptedConn(hello(0x71), probe(7))
	done, stop := pump(t, c)
	defer stop()
	// Silent from the echo on; the reaper's backstop (800 ms) ends it, so
	// everything the keepalive does happens inside that window.
	ended(done, 750*time.Millisecond)
	got, at := c.writes()
	if len(got) == 0 || string(got[0]) != string(probe(7)) {
		t.Fatalf("the probe was not echoed first: %d write(s)", len(got))
	}
	repeats := got[1:]
	if len(repeats) < 2 {
		t.Fatalf("a connection silent for 750 ms got %d repeat(s), want at least 2 "+
			"(the first after %s, then every %s)", len(repeats), keepaliveAfter, keepaliveEvery)
	}
	for i, r := range repeats {
		if string(r) != string(probe(7)) {
			t.Fatalf("repeat %d is not the last echo byte for byte: % x", i, r)
		}
	}
	// Not before the silence has lasted keepaliveAfter (one tick of slack).
	if gap := at[1].Sub(at[0]); gap < keepaliveAfter-groupReapEvery {
		t.Fatalf("the first repeat came %s after the echo, before the silence was %s long", gap, keepaliveAfter)
	}
	for i := 2; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < keepaliveEvery-groupReapEvery {
			t.Fatalf("repeats %d and %d are %s apart, want at least %s", i-1, i, gap, keepaliveEvery)
		}
	}
}

// Nothing is ever invented: a connection that never echoed a probe — a client
// that does not probe — gets no packet from the keepalive, however silent.
func TestNoRepeatBeforeAnEcho(t *testing.T) {
	c := newScriptedConn(hello(0x72))
	_, stop := pump(t, c)
	defer stop()
	time.Sleep(600 * time.Millisecond)
	if got, _ := c.writes(); len(got) != 0 {
		t.Fatalf("a connection that never echoed a probe received %d packet(s): % x", len(got), got[0])
	}
}

// A connection that keeps talking is never silent, so it gets echoes and
// nothing else — a repeat there could overtake the pong its own ping earns.
func TestARepeatIsNotSentWhileTheClientSpeaks(t *testing.T) {
	pkts := [][]byte{hello(0x73)}
	for seq := uint64(1); seq <= 7; seq++ {
		pkts = append(pkts, probe(seq))
	}
	c := newTickingConn(100*time.Millisecond, pkts...)
	_, stop := pump(t, c)
	defer stop()
	time.Sleep(900 * time.Millisecond) // the seven probes take 700 ms; then 200 ms of silence at most
	got, _ := c.writes()
	if len(got) != 7 {
		t.Fatalf("a client probing every 100 ms got %d write(s), want exactly its 7 echoes", len(got))
	}
	for i, w := range got {
		if string(w) != string(probe(uint64(i+1))) {
			t.Fatalf("write %d is not the echo of probe %d: % x", i, i+1, w)
		}
	}
}

// Every connection of a group is kept alive on its own, with its OWN last
// echo — one packet a minute on one connection was the single point of failure.
func TestEveryConnectionGetsItsOwnRepeat(t *testing.T) {
	a := newScriptedConn(hello(0x74), probe(1))
	b := newScriptedConn(hello(0x74), probe(2))
	_, stopA := pump(t, a)
	defer stopA()
	_, stopB := pump(t, b)
	defer stopB()
	time.Sleep(600 * time.Millisecond)
	for name, c := range map[string]*scriptedConn{"a": a, "b": b} {
		got, _ := c.writes()
		if len(got) < 2 {
			t.Fatalf("conn %s got %d write(s), want its echo and at least one repeat", name, len(got))
		}
		for i, w := range got {
			if string(w) != string(got[0]) {
				t.Fatalf("conn %s: write %d differs from its own echo — % x vs % x", name, i, w, got[0])
			}
		}
	}
	ga, _ := a.writes()
	gb, _ := b.writes()
	if string(ga[0]) == string(gb[0]) {
		t.Fatal("fixture: the two connections echoed the same bytes, the test cannot tell them apart")
	}
}

// The reaper that knows: a member silent for reapZombieAfter while the group
// keeps hearing another member is a zombie and goes before the backstop; the
// live neighbour stays.
func TestAZombieBesideALiveNeighbourIsReapedEarly(t *testing.T) {
	live := [][]byte{hello(0x75)}
	for seq := uint64(1); seq <= 12; seq++ {
		live = append(live, probe(seq))
	}
	a := newTickingConn(100*time.Millisecond, live...) // talks for 1.2 s
	b := newScriptedConn(hello(0x75), probe(1))        // one probe, then silence
	before := reapsByReason[reapZombie].Load()
	doneA, stopA := pump(t, a)
	defer stopA()
	doneB, stopB := pump(t, b)
	defer stopB()
	if ended(doneB, reapZombieAfter-2*groupReapEvery) {
		t.Fatal("the silent member was reaped before reapZombieAfter")
	}
	if !ended(doneB, groupIdleTimeout-reapZombieAfter) {
		t.Fatalf("a member silent beside a live neighbour was not reaped before the %s backstop", groupIdleTimeout)
	}
	if ended(doneA, 100*time.Millisecond) {
		t.Fatal("the LIVE neighbour was reaped too")
	}
	if n := reapsByReason[reapZombie].Load() - before; n != 1 {
		t.Fatalf("zombie reaps counted: %d, want 1", n)
	}
}

// A group that is wholly silent is NOT a zombie's — it is reaped at the backstop
// exactly as before, and not a moment earlier: with repeats going out, silence
// that long means they did not wake the client. 🚫 And never kept longer: a
// group left behind by a network switch is silent in the same way.
func TestAWhollySilentGroupIsReapedAtTheBackstopAsBefore(t *testing.T) {
	a := newScriptedConn(hello(0x76), probe(1))
	b := newScriptedConn(hello(0x76), probe(2))
	before := reapsByReason[reapIdle].Load()
	doneA, stopA := pump(t, a)
	defer stopA()
	doneB, stopB := pump(t, b)
	defer stopB()
	if ended(doneA, groupIdleTimeout-2*groupReapEvery) || ended(doneB, 0) {
		t.Fatal("a wholly silent group was reaped before the backstop — a sleeping client cut off early")
	}
	if !ended(doneA, 500*time.Millisecond) || !ended(doneB, 500*time.Millisecond) {
		t.Fatalf("a wholly silent group was kept past the %s backstop", groupIdleTimeout)
	}
	if n := reapsByReason[reapIdle].Load() - before; n != 2 {
		t.Fatalf("idle reaps counted: %d, want 2", n)
	}
}

// The client says which group it left: its new connections carry the sentinel,
// and the old group's members are reaped at their next tick — no repeat goes
// into released allocations. The sentinel is consumed, never forwarded; one
// naming the sender's own group, or no group at all, does nothing.
func TestASupersedeSentinelReapsTheOldGroup(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()
	target := wgSide.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := func(c *scriptedConn) chan struct{} {
		done := make(chan struct{})
		go func() { defer close(done); pumpBidirectional(ctx, c, target, false) }()
		return done
	}
	keyA, keyB := groupKey{}, groupKey{}
	for i := range keyA {
		keyA[i], keyB[i] = 0x77, 0x78
	}
	// The old group: two connections that echoed a probe and are now silent.
	a1, a2 := newScriptedConn(hello(0x77), probe(1)), newScriptedConn(hello(0x77), probe(2))
	doneA1, doneA2 := run(a1), run(a2)
	defer a1.Close()
	defer a2.Close()
	time.Sleep(100 * time.Millisecond)
	if !hasGroup(keyA) {
		t.Fatal("fixture: the old group never formed")
	}
	before := reapsByReason[reapSuperseded].Load()
	// The new group: its connection names its own group first (ignored), then
	// an unknown one (ignored), then the old one — and carries data after it.
	payload := []byte{4, 0, 0, 0, 'd', 'a', 't', 'a'}
	b := newScriptedConn(hello(0x78), supersede(0x78), supersede(0x79), supersede(0x77), payload)
	doneB := run(b)
	defer b.Close()
	if !ended(doneA1, 400*time.Millisecond) || !ended(doneA2, 200*time.Millisecond) {
		t.Fatal("the superseded group's connections were not reaped at their next tick")
	}
	if ended(doneB, 50*time.Millisecond) {
		t.Fatal("the NEW group's connection was reaped — a sentinel naming its own group must do nothing")
	}
	if hasGroup(keyA) {
		t.Fatal("the superseded group's hub was not released")
	}
	if !hasGroup(keyB) {
		t.Fatal("the new group is gone")
	}
	if n := reapsByReason[reapSuperseded].Load() - before; n != 2 {
		t.Fatalf("superseded reaps counted: %d, want 2", n)
	}
	// What WireGuard saw from the new connection: the data packet and not one
	// sentinel.
	_ = wgSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1600)
	n, _, err := wgSide.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("WireGuard side received nothing: %v", err)
	}
	if _, isSup := isGroupSupersede(buf[:n]); isSup {
		t.Fatal("a supersede sentinel was forwarded to WireGuard instead of being consumed")
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("WireGuard got %q, want the data packet %q", buf[:n], payload)
	}
	// A late or lost sentinel: naming a group that no longer exists is a no-op.
	if groups.supersede(keyA, keyB) {
		t.Fatal("superseding a group that is already gone reported success")
	}
}

// A repeat whose write fails ends the connection, like a failed echo does, and
// is counted: the relay leg is dead, and a connection that cannot be written to
// is not kept on the strength of its silence.
func TestAFailedRepeatEndsTheConnection(t *testing.T) {
	c := newScriptedConn(hello(0x79), probe(1))
	c.failAt = 1 // the echo goes through, the first repeat fails
	before := keepaliveWriteFails.Load()
	done, stop := pump(t, c)
	defer stop()
	if !ended(done, keepaliveAfter+3*groupReapEvery) {
		t.Fatal("a connection whose repeat could not be written lived on")
	}
	if n := keepaliveWriteFails.Load() - before; n != 1 {
		t.Fatalf("failed repeats counted: %d, want 1", n)
	}
}

// The rules as a table, on a clock in the test's hands: what one tick decides
// from the two stamps, the group's flag and whether an echo exists.
func TestTheClockworksRules(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	mk := func() *clockwork {
		return &clockwork{after: 45 * time.Second, every: 60 * time.Second,
			zombie: 90 * time.Second, neighbour: 60 * time.Second, idle: 150 * time.Second}
	}
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	type step struct {
		name       string
		in         clockworkInput
		wantRepeat bool
		wantReap   reapReason
	}
	run := func(t *testing.T, cw *clockwork, steps []step) {
		t.Helper()
		for _, s := range steps {
			repeat, reap := cw.step(s.in)
			if repeat != s.wantRepeat || reap != s.wantReap {
				t.Fatalf("%s: got repeat=%v reap=%s, want repeat=%v reap=%s", s.name, repeat, reap, s.wantRepeat, s.wantReap)
			}
			if repeat {
				cw.repeated(s.in.now) // the caller stamps what it WROTE
			}
		}
	}
	grouped := func(now, last, group float64, echo bool) clockworkInput {
		return clockworkInput{now: at(now), lastInbound: at(last), groupLastInbound: at(group), grouped: true, haveEcho: echo}
	}
	t.Run("the repeat: after the silence, then every interval, never before an echo", func(t *testing.T) {
		run(t, mk(), []step{
			{"silent 30 s", grouped(30, 0, 0, true), false, reapNone},
			{"silent 44 s", grouped(44, 0, 0, true), false, reapNone},
			{"silent 45 s → the first repeat", grouped(45, 0, 0, true), true, reapNone},
			{"silent 60 s → too soon after the first", grouped(60, 0, 0, true), false, reapNone},
			{"silent 104 s → still 59 s since it", grouped(104, 0, 0, true), false, reapNone},
			{"silent 105 s → the second repeat", grouped(105, 0, 0, true), true, reapNone},
		})
		run(t, mk(), []step{
			{"silent 120 s with no echo ever", grouped(120, 0, 0, false), false, reapNone},
		})
	})
	t.Run("any inbound restarts the silence", func(t *testing.T) {
		run(t, mk(), []step{
			{"silent 45 s → repeat", grouped(45, 0, 0, true), true, reapNone},
			{"heard at 50 s; at 80 s the silence is 30 s", grouped(80, 50, 50, true), false, reapNone},
			{"at 95 s the silence is 45 s again, 50 s since the repeat", grouped(95, 50, 50, true), false, reapNone},
			{"at 110 s: 60 s since the repeat", grouped(110, 50, 50, true), true, reapNone},
		})
	})
	t.Run("a repeat the gate held back is not stamped: the next silence's first repeat is not delayed", func(t *testing.T) {
		cw := mk()
		if repeat, _ := cw.step(grouped(45, 0, 0, true)); !repeat {
			t.Fatal("fixture: no repeat decided at 45 s")
		}
		// Not stamped: the client spoke and the gate wrote nothing.
		run(t, cw, []step{
			{"heard at 46 s; at 91 s the silence is 45 s again → a repeat, not 60 s after the held one", grouped(91, 46, 46, true), true, reapNone},
		})
	})
	t.Run("the repeats are off at every 0", func(t *testing.T) {
		cw := mk()
		cw.every = 0
		run(t, cw, []step{{"silent 300 s", grouped(120, 0, 0, true), false, reapNone}})
	})
	t.Run("the reaper: a zombie beside a heard neighbour, the backstop, a superseded group", func(t *testing.T) {
		run(t, mk(), []step{
			{"silent 90 s, neighbour heard 30 s ago → not yet (needs more than 90): a repeat instead", grouped(90, 0, 60, true), true, reapNone},
			{"silent 91 s, neighbour heard 31 s ago → zombie", grouped(91, 0, 60, true), false, reapZombie},
		})
		run(t, mk(), []step{
			{"silent 100 s, neighbour heard 60 s ago → not within the minute: no zombie, a repeat instead", grouped(100, 0, 40, true), true, reapNone},
			{"silent 151 s, nobody heard → the backstop", grouped(151, 0, 0, true), false, reapIdle},
		})
		run(t, mk(), []step{
			{"a lone member: the group's stamp is its own → never a zombie, a repeat instead", grouped(120, 0, 0, true), true, reapNone},
		})
		cw := mk()
		in := grouped(10, 0, 5, true)
		in.superseded = true
		run(t, cw, []step{{"superseded: reaped at once, no repeat, whatever the silence", in, false, reapSuperseded}})
	})
	t.Run("an ungrouped connection is never reaped but is kept alive", func(t *testing.T) {
		run(t, mk(), []step{
			{"silent 400 s, per-conn mode", clockworkInput{now: at(400), lastInbound: at(0), haveEcho: true}, true, reapNone},
		})
	})
}

// The recognizer, exactly: nothing else may be mistaken for the sentinel, or a
// WireGuard packet would be swallowed — and a hello is not a supersede.
func TestIsGroupSupersede(t *testing.T) {
	k, ok := isGroupSupersede(supersede(0xab))
	if !ok {
		t.Fatal("a well-formed sentinel was not recognised")
	}
	for _, b := range k {
		if b != 0xab {
			t.Fatalf("group id mis-parsed: %x", k)
		}
	}
	for name, pkt := range map[string][]byte{
		"a hello":           hello(0xab),
		"a probe":           probe(1),
		"magic but short":   append(append([]byte(nil), groupSupersedeMagic...), 1, 2, 3),
		"magic but long":    append(supersede(1), 0),
		"right length, wg":  make([]byte, groupHelloLen),
		"empty":             {},
		"wrong third byte":  {0xff, 'S', 'X', 'P', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		"not 0xff-prefixed": {0x04, 'S', 'U', 'P', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	} {
		if _, ok := isGroupSupersede(pkt); ok {
			t.Fatalf("%s was mistaken for a supersede sentinel", name)
		}
	}
	if _, ok := isGroupHello(supersede(1)); ok {
		t.Fatal("a supersede sentinel was mistaken for a hello")
	}
}

// The numbers as shipped are the user's (2026-09-22): 45 / 60 / 90 s, and the
// neighbour window a minute. TestMain shrinks the vars; the defaults live on in
// the constants the flags are declared from.
func TestTheNumbersAsShipped(t *testing.T) {
	if defaultKeepaliveAfter != 45*time.Second || defaultKeepaliveEvery != 60*time.Second ||
		defaultReapZombieAfter != 90*time.Second || defaultZombieNeighbourWithin != 60*time.Second {
		t.Fatalf("the shipped numbers moved: %s / %s / %s / %s", defaultKeepaliveAfter, defaultKeepaliveEvery,
			defaultReapZombieAfter, defaultZombieNeighbourWithin)
	}
	if defaultKeepaliveEvery >= 150*time.Second || defaultKeepaliveAfter+2*defaultKeepaliveEvery >= 300*time.Second {
		t.Fatal("the repeats must come faster than the 150-s reaper and twice inside a 300-s NAT state")
	}
}

// A connection must survive its own promotion. Between promote's bind.Store and
// its bindCancel the outbound goroutine can already be running the NEW binding
// under the OLD context; the cancel then ended that run, the bindings compared
// equal, and the connection was torn down the moment it joined its group. Seen
// as a flaky reap in this suite: a hello as the very first packet is the race's
// shape. Many rounds, because the window is a few microseconds wide.
func TestAConnectionSurvivesItsOwnPromotion(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()
	target := wgSide.LocalAddr().String()
	// Batches of concurrent pumps: the window is a few microseconds wide and
	// contention is what opens it — 200 sequential rounds caught the restored
	// race three times in four.
	const batches, perBatch = 20, 100
	for b := 0; b < batches; b++ {
		ctx, cancel := context.WithCancel(context.Background())
		conns := make([]*scriptedConn, perBatch)
		dones := make([]chan struct{}, perBatch)
		for i := range conns {
			conns[i] = newScriptedConn(hello(0x7a), probe(1))
			dones[i] = make(chan struct{})
			go func(c *scriptedConn, done chan struct{}) {
				defer close(done)
				pumpBidirectional(ctx, c, target, false)
			}(conns[i], dones[i])
		}
		time.Sleep(30 * time.Millisecond)
		for i, done := range dones {
			if ended(done, 0) {
				t.Fatalf("batch %d, connection %d: ended at its promotion", b, i)
			}
		}
		cancel()
		for i := range conns {
			conns[i].Close()
			<-dones[i]
		}
	}
}

// The gate alone: before any echo it writes nothing at all — not even an empty
// packet — and a repeat the gate held back leaves the clockwork's stamp alone,
// while one it wrote is stamped.
func TestTheGateWritesNothingBeforeAnEchoAndStampsOnlyWhatItWrote(t *testing.T) {
	conn := &fakeConn{}
	var echo lastEcho
	var lastInbound atomic.Int64
	lastInbound.Store(time.Now().Add(-time.Minute).UnixNano())
	cw := &clockwork{after: 200 * time.Millisecond, every: 150 * time.Millisecond}
	if sent, err := cw.send(conn, &lastInbound, &echo, time.Now()); err != nil || sent {
		t.Fatalf("before any echo: sent=%v err=%v", sent, err)
	}
	if n := conn.count(); n != 0 {
		t.Fatalf("before any echo %d packet(s) were written", n)
	}
	if err := echo.echo(conn, probe(3)); err != nil {
		t.Fatal(err)
	}
	lastInbound.Store(time.Now().UnixNano()) // the client has just spoken
	if sent, _ := cw.send(conn, &lastInbound, &echo, time.Now()); sent || !cw.lastRepeat.IsZero() {
		t.Fatalf("a repeat held back by the gate: sent=%v, stamped=%v", sent, !cw.lastRepeat.IsZero())
	}
	lastInbound.Store(time.Now().Add(-time.Minute).UnixNano())
	now := time.Now()
	if sent, _ := cw.send(conn, &lastInbound, &echo, now); !sent || !cw.lastRepeat.Equal(now) {
		t.Fatalf("a repeat written: sent=%v, stamped at the write=%v", sent, cw.lastRepeat.Equal(now))
	}
	if n := conn.count(); n != 2 {
		t.Fatalf("the wire carries %d packet(s), want the echo and one repeat", n)
	}
}

// THE REVIEW'S INTERLEAVING (2026-09-22). The clockwork decided to repeat seq 1;
// before its write, the inbound pump read a fresh ping seq 2 and echoed it;
// then the prepared repeat of seq 1 went out — and a client from before build
// 422, whose pong handler stores the seq unconditionally, moved its mark back
// and missed the answer its probe had earned. The repeat now re-reads the
// silence under the echo's own lock right before it writes: a client that has
// spoken since the tick decided gets no repeat, and a repeat is never written
// behind a fresher echo.
func TestARepeatNeverFollowsAFresherEcho(t *testing.T) {
	t.Run("the client spoke between the decision and the write: nothing is written", func(t *testing.T) {
		conn := &fakeConn{}
		var echo lastEcho
		var lastInbound atomic.Int64
		lastInbound.Store(time.Now().Add(-time.Minute).UnixNano())
		if err := echo.echo(conn, probe(1)); err != nil {
			t.Fatal(err)
		}
		cw := &clockwork{after: 200 * time.Millisecond, every: 150 * time.Millisecond, zombie: time.Hour, neighbour: time.Hour, idle: time.Hour}
		in := clockworkInput{now: time.Now(), lastInbound: time.Unix(0, lastInbound.Load()), haveEcho: true}
		if repeat, _ := cw.step(in); !repeat {
			t.Fatal("fixture: the tick did not decide to repeat")
		}
		// The inbound pump, between the decision and the write: a fresh ping.
		lastInbound.Store(time.Now().UnixNano())
		if err := echo.echo(conn, probe(2)); err != nil {
			t.Fatal(err)
		}
		sent, err := echo.repeat(conn, &lastInbound, cw.after)
		if err != nil {
			t.Fatal(err)
		}
		if sent {
			t.Fatal("a repeat was written behind a fresher echo")
		}
		conn.mu.Lock()
		defer conn.mu.Unlock()
		if len(conn.got) != 2 || string(conn.got[1]) != string(probe(2)) {
			t.Fatalf("the wire carries %d packet(s), want the two echoes only", len(conn.got))
		}
	})
	t.Run("under contention the seq on the wire never goes backwards", func(t *testing.T) {
		conn := &fakeConn{}
		var echo lastEcho
		var lastInbound atomic.Int64
		lastInbound.Store(time.Now().Add(-time.Minute).UnixNano())
		if err := echo.echo(conn, probe(1)); err != nil {
			t.Fatal(err)
		}
		const pings = 400
		done := make(chan struct{})
		go func() {
			defer close(done)
			for seq := uint64(2); seq <= pings; seq++ {
				// The inbound pump: the read stamps, then the echo.
				lastInbound.Store(time.Now().UnixNano())
				_ = echo.echo(conn, probe(seq))
				if seq%7 == 0 {
					// Now and then a silence long enough for a repeat to be due.
					lastInbound.Store(time.Now().Add(-time.Minute).UnixNano())
				}
			}
		}()
		for i := 0; i < 4000; i++ {
			_, _ = echo.repeat(conn, &lastInbound, 100*time.Millisecond)
		}
		<-done
		conn.mu.Lock()
		defer conn.mu.Unlock()
		var last uint64
		repeats := 0
		for i, pkt := range conn.got {
			seq := binary.BigEndian.Uint64(pkt[4:])
			if seq < last {
				t.Fatalf("write %d carries seq %d behind seq %d — a repeat landed after a fresher echo", i, seq, last)
			}
			if seq == last {
				repeats++
			}
			last = seq
		}
		if repeats == 0 {
			t.Fatal("fixture: not one repeat was written — the test exercised nothing")
		}
	})
}
