package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// 2026-11-08, the failover run on build 477 (Nov 8 §603): the client re-dialled
// its forty sessions within 1.5 s of the mark, but the server kept the forty
// DEAD members in the group until its zombie reaper came (+77 … +93 s) — and the
// downlink hub hands a packet to whichever member's goroutine has WAITED LONGEST
// on the shared channel, so the dead members, queued since the black-out, took
// the next ≈40 packets (WireGuard's handshake responses, the SYN-ACKs) and the
// tunnel stayed deaf ≈28 s; the first download after the failover timed out.
// Now the client names, behind the hello of a new session and again behind
// every tick's ping, the connection it REPLACES (its own index), and the server
// ends the predecessor at once.

func repDecl(idx uint16, gen uint64) []byte {
	b := make([]byte, groupHelloLen)
	copy(b, groupReplaceMagic)
	binary.BigEndian.PutUint16(b[4:], idx)
	binary.BigEndian.PutUint64(b[6:], gen)
	return b
}

func TestIsGroupReplace(t *testing.T) {
	if _, _, ok := isGroupReplace(repDecl(3, 1)[:groupHelloLen-1]); ok {
		t.Fatal("a 19-byte packet read as a replacement")
	}
	if _, _, ok := isGroupReplace(append(repDecl(3, 1), 0)); ok {
		t.Fatal("a 21-byte packet read as a replacement")
	}
	for i := 0; i < 4; i++ {
		bad := repDecl(3, 1)
		bad[i] ^= 0x01
		if _, _, ok := isGroupReplace(bad); ok {
			t.Fatalf("magic byte %d not checked", i)
		}
	}
	for name, other := range map[string][]byte{"hello": hello(0x7a), "pace": paceDecl(5)} {
		if _, _, ok := isGroupReplace(other); ok {
			t.Fatalf("a %s sentinel read as a replacement", name)
		}
	}
	if idx, gen, ok := isGroupReplace(repDecl(0x1234, 0x0102030405060708)); !ok || idx != 0x1234 || gen != 0x0102030405060708 {
		t.Fatalf("got %d %x %v, want 0x1234 / 0x0102030405060708 (big-endian)", idx, gen, ok)
	}
}

// pumped is one connection through pumpBidirectional against a fake WireGuard
// side; the payload behind its sentinels is read there, so the sentinels are
// known consumed by the time it returns.
type pumped struct {
	c    *scriptedConn
	done chan struct{}
	st   *connStat
	from *net.UDPAddr // the hub's socket, where the WireGuard side sends the downlink
}

func runPumped(t *testing.T, ctx context.Context, wgSide *net.UDPConn, payload byte, pkts ...[]byte) *pumped {
	t.Helper()
	before := registry.ids()
	data := []byte{4, 0, 0, 0, payload}
	c := newScriptedConn(append(pkts, data)...)
	done := make(chan struct{})
	go func() { defer close(done); pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false) }()
	t.Cleanup(func() { c.Close(); <-done })
	_ = wgSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1600)
	n, from, err := wgSide.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("payload %x never reached the WireGuard side: %v", payload, err)
	}
	if n != len(data) || buf[n-1] != payload {
		t.Fatalf("the WireGuard side read %d bytes ending %x, want payload %x alone (a sentinel forwarded?)", n, buf[n-1], payload)
	}
	var st *connStat
	for id := range registry.ids() {
		if !before[id] {
			st = registry.get(id)
		}
	}
	if st == nil {
		t.Fatal("the connection's connStat not found")
	}
	return &pumped{c: c, done: done, st: st, from: from}
}

// withPatientReaper: the package's tests run the reaper on a sub-second scale
// (group_test.go); these tests keep several members alive while others speak,
// so a silent one must not be read as a zombie meanwhile.
func withPatientReaper(t *testing.T) {
	t.Helper()
	prevZ, prevI := reapZombieAfter, groupIdleTimeout
	reapZombieAfter, groupIdleTimeout = 30*time.Second, 30*time.Second
	t.Cleanup(func() { reapZombieAfter, groupIdleTimeout = prevZ, prevI })
}

func pumpEnded(p *pumped, within time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(within):
		return false
	}
}

func TestAReplacementEndsThePredecessor(t *testing.T) {
	withPatientReaper(t)
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wgSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replacedBefore := reapsByReason[reapReplaced].Load()
	a := runPumped(t, ctx, wgSide, 'a', hello(0x7b), repDecl(3, 1))
	// The successor of the client's connection 3: the predecessor ends at once.
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7b), repDecl(3, 2))
	if !pumpEnded(a, 3*time.Second) {
		t.Fatal("the predecessor still runs after its successor declared itself")
	}
	if got := a.st.reaped.Load(); got != int64(reapReplaced) {
		t.Fatalf("the predecessor's reap reason is %d, want replaced (%d)", got, reapReplaced)
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 1 {
		t.Fatalf("replaced counter moved by %d, want 1", got)
	}
	if pumpEnded(b, 300*time.Millisecond) {
		t.Fatal("the successor ended with its predecessor")
	}
	// Another index: nobody's predecessor.
	c := runPumped(t, ctx, wgSide, 'c', hello(0x7b), repDecl(4, 3))
	if pumpEnded(b, 300*time.Millisecond) {
		t.Fatalf("a replacement of another index ended member b (reap reason %d)", b.st.reaped.Load())
	}
	if pumpEnded(c, 100*time.Millisecond) {
		t.Fatalf("the member that replaced another index ended itself (reap reason %d)", c.st.reaped.Load())
	}
	// A repeat of the same word from the same connection (every tick's ping): a no-op.
	d := runPumped(t, ctx, wgSide, 'd', hello(0x7b), repDecl(5, 4), repDecl(5, 4), repDecl(5, 4))
	if pumpEnded(d, 300*time.Millisecond) {
		t.Fatal("a repeated replacement ended its own sender")
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 1 {
		t.Fatalf("replaced counter moved by %d over the run, want 1", got)
	}
}

// A member that ended on its own frees its index: the next connection with that
// index finds no predecessor (and no stale cancel is kept).
func TestAMemberThatEndedFreesItsIndex(t *testing.T) {
	withPatientReaper(t)
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wgSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keep := runPumped(t, ctx, wgSide, 'k', hello(0x7c)) // keeps the group alive
	replacedBefore := reapsByReason[reapReplaced].Load()
	a := runPumped(t, ctx, wgSide, 'a', hello(0x7c), repDecl(6, 1))
	a.c.Close()
	if !pumpEnded(a, 3*time.Second) {
		t.Fatal("the fixture: the closed connection's pump did not return")
	}
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7c), repDecl(6, 2))
	if pumpEnded(b, 300*time.Millisecond) || pumpEnded(keep, 100*time.Millisecond) {
		t.Fatal("a replacement after the predecessor's own end ended a live member")
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 0 {
		t.Fatalf("replaced counter moved by %d, want 0 (nobody was replaced)", got)
	}
}

// A replacement that arrives before the hello (the two can swap on the UDP leg)
// is ignored — the next tick's repeat claims the index; until then nobody is
// touched.
func TestAReplacementBeforeTheHelloIsIgnored(t *testing.T) {
	withPatientReaper(t)
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wgSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replacedBefore := reapsByReason[reapReplaced].Load()
	a := runPumped(t, ctx, wgSide, 'a', repDecl(7, 1), hello(0x7d))
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7d), repDecl(7, 2))
	if pumpEnded(a, 300*time.Millisecond) {
		t.Fatal("a replacement sent before the hello claimed the index")
	}
	c := runPumped(t, ctx, wgSide, 'c', hello(0x7d), repDecl(7, 3))
	if !pumpEnded(b, 3*time.Second) || pumpEnded(a, 100*time.Millisecond) || pumpEnded(c, 100*time.Millisecond) {
		t.Fatal("the claim after the hello did not end its predecessor alone")
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 1 {
		t.Fatalf("replaced counter moved by %d, want 1", got)
	}
}

// The user's review of b1372eb: the sentinel carried the index alone, so the
// ORDER of arrival decided who the successor was — a late first sentinel of the
// old session ended its healthy successor, and a repeat the old session had read
// before its end took the index back and ended both. Now the sentinel carries
// the session's GENERATION (the client's hand-out stamp: fixed for one session,
// higher for every later one on the index) and the server keeps the highest
// generation accepted per index — a lower one never displaces, whoever sends it,
// and the highest is kept after its holder leaves.

// runPacedPumped: like runPumped, with per-packet delays before each read and
// the packets given whole — the payload (read at the WireGuard side) where the
// caller puts it, so that a sentinel can follow it after a delay.
func runPacedPumped(t *testing.T, ctx context.Context, wgSide *net.UDPConn, payload byte, delays []time.Duration, pkts ...[]byte) *pumped {
	t.Helper()
	before := registry.ids()
	data := []byte{4, 0, 0, 0, payload}
	c := newPacedConn(delays, pkts...)
	done := make(chan struct{})
	go func() { defer close(done); pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false) }()
	t.Cleanup(func() { c.Close(); <-done })
	_ = wgSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1600)
	n, from, err := wgSide.ReadFromUDP(buf)
	if err != nil || n != len(data) || buf[n-1] != payload {
		t.Fatalf("payload %x: %v / %d bytes", payload, err, n)
	}
	var st *connStat
	for id := range registry.ids() {
		if !before[id] {
			st = registry.get(id)
		}
	}
	return &pumped{c: c, done: done, st: st, from: from}
}

func TestALateSentinelOfTheOldSessionDoesNotEndItsSuccessor(t *testing.T) {
	withPatientReaper(t)
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wgSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replacedBefore := reapsByReason[reapReplaced].Load()
	// A's first sentinel (generation 1) is delayed 700 ms behind its hello and payload.
	a := runPacedPumped(t, ctx, wgSide, 'a', []time.Duration{0, 0, 700 * time.Millisecond}, hello(0x7e), []byte{4, 0, 0, 0, 'a'}, repDecl(3, 1))
	// B, the newer session of the same index (generation 2), claims meanwhile.
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7e), repDecl(3, 2))
	// A's late sentinel arrives, generation 1 below the bar 2: B stays — and A,
	// the predecessor that outlived its replacement, ENDS (the user's review of
	// a316b3c: a bare return from claim left A a member and a consumer of the
	// group's queue — 10 of the next 20 downlink packets went to it).
	if pumpEnded(b, 1200*time.Millisecond) {
		t.Fatal("the successor ended on the old session's late sentinel")
	}
	if !pumpEnded(a, 3*time.Second) {
		t.Fatal("the old session's late sentinel ended nobody — A stays a member and takes from the group's queue")
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 1 {
		t.Fatalf("the replaced count moved by %d, want 1 — A, the stale sender", got)
	}
	if r := reapReason(a.st.reaped.Load()); r != reapReplaced {
		t.Fatalf("A's reap reason %v, want replaced", r)
	}
	// The downlink after it: every packet to B, none to A.
	aBefore, _ := a.c.writes()
	bBefore, _ := b.c.writes()
	for i := 0; i < 20; i++ {
		if _, err := wgSide.WriteToUDP([]byte{4, 0, 0, 0, byte(i)}, b.from); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		got, _ := b.c.writes()
		if len(got)-len(bBefore) >= 20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B received %d of the 20 downlink packets", len(got)-len(bBefore))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got, _ := a.c.writes(); len(got) != len(aBefore) {
		t.Fatalf("A, ended, still received %d downlink packet(s)", len(got)-len(aBefore))
	}
}

// At the hub: a displaced session's repeat (its generation, read before its end)
// takes nothing back; after the holder leaves, the highest generation accepted is
// still the bar; a higher generation from another connection displaces. And (the
// user's review of a316b3c) a claim STRICTLY OLDER than the bar from a connection
// that is not the holder ends THAT connection — a predecessor that outlived its
// replacement would go on taking from the group's queue — while the holder
// stays; a claim AT the bar from another connection ends nobody.
func TestADisplacedSessionNeverTakesTheIndexBack(t *testing.T) {
	h := &downlinkHub{}
	a, b, c, d, e := &connStat{id: 1}, &connStat{id: 2}, &connStat{id: 3}, &connStat{id: 4}, &connStat{id: 5}
	cancels := map[*connStat]int{}
	cancelOf := func(st *connStat) func() { return func() { cancels[st]++ } }
	replacedBefore := reapsByReason[reapReplaced].Load()
	if prev, stale := h.claim(3, 1, a, cancelOf(a)); prev != nil || stale {
		t.Fatalf("A's first claim: prev %v stale %v, want neither", prev, stale)
	}
	if prev, stale := h.claim(3, 2, b, cancelOf(b)); prev != a || stale || cancels[a] != 1 {
		t.Fatalf("B's claim: prev %v stale %v cancels[a] %d, want A displaced once", prev, stale, cancels[a])
	}
	// A's repeat, read before its end: A is already ending — nothing more, B untouched.
	if prev, stale := h.claim(3, 1, a, cancelOf(a)); prev != nil || stale || cancels[b] != 0 || cancels[a] != 1 {
		t.Fatalf("A's repeat after its end: prev %v stale %v cancels a %d b %d", prev, stale, cancels[a], cancels[b])
	}
	// B's own repeat: nothing.
	if prev, stale := h.claim(3, 2, b, cancelOf(b)); prev != nil || stale || cancels[b] != 0 {
		t.Fatalf("B's own repeat: prev %v stale %v cancels[b] %d", prev, stale, cancels[b])
	}
	// D, an older session of the index that was never a holder (its first copy
	// late behind B's claim), generation 1 below the bar 2: D ends, B stays.
	if prev, stale := h.claim(3, 1, d, cancelOf(d)); prev != nil || !stale || cancels[d] != 1 || cancels[b] != 0 || h.holder(3) != b {
		t.Fatalf("D's stale claim: prev %v stale %v cancels d %d b %d holder %v — want D ended, B the holder", prev, stale, cancels[d], cancels[b], h.holder(3))
	}
	if r := reapReason(d.reaped.Load()); r != reapReplaced {
		t.Fatalf("D's reap reason %v, want replaced", r)
	}
	// D's repeat: already ending — nothing more.
	if prev, stale := h.claim(3, 1, d, cancelOf(d)); prev != nil || stale || cancels[d] != 1 {
		t.Fatalf("D's repeat: prev %v stale %v cancels[d] %d", prev, stale, cancels[d])
	}
	// E AT the bar (generation 2) from another connection: not strictly older — nobody ends.
	if prev, stale := h.claim(3, 2, e, cancelOf(e)); prev != nil || stale || cancels[e] != 0 || cancels[b] != 0 || h.holder(3) != b {
		t.Fatalf("E at the bar: prev %v stale %v cancels e %d b %d holder %v — want nothing", prev, stale, cancels[e], cancels[b], h.holder(3))
	}
	// B leaves; A's stale sentinel still finds the bar at 2 (A already ending: nothing).
	h.leave(b)
	if prev, stale := h.claim(3, 1, a, cancelOf(a)); prev != nil || stale || cancels[a] != 1 {
		t.Fatalf("A after B left: prev %v stale %v cancels[a] %d", prev, stale, cancels[a])
	}
	if h.holder(3) != nil {
		t.Fatal("the index has a holder after B left")
	}
	// C, generation 3: the index is its.
	if prev, stale := h.claim(3, 3, c, cancelOf(c)); prev != nil || stale || h.holder(3) != c {
		t.Fatalf("C's claim: prev %v stale %v holder %v", prev, stale, h.holder(3))
	}
	// The holder's own repeat, even with a number above its own: never its own end.
	if prev, stale := h.claim(3, 9, c, cancelOf(c)); prev != nil || stale || cancels[c] != 0 || h.holder(3) != c {
		t.Fatalf("the holder's repeat: prev %v stale %v cancels[c] %d holder %v", prev, stale, cancels[c], h.holder(3))
	}
	if cancels[a] != 1 || cancels[b] != 0 || cancels[c] != 0 || cancels[d] != 1 || cancels[e] != 0 {
		t.Fatalf("cancels a %d b %d c %d d %d e %d, want 1 0 0 1 0", cancels[a], cancels[b], cancels[c], cancels[d], cancels[e])
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 2 {
		t.Fatalf("the replaced count moved by %d, want 2 — A displaced, D stale", got)
	}
}
