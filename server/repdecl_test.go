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

func repDecl(idx uint16) []byte {
	b := make([]byte, groupHelloLen)
	copy(b, groupReplaceMagic)
	binary.BigEndian.PutUint16(b[4:], idx)
	return b
}

func TestIsGroupReplace(t *testing.T) {
	if _, ok := isGroupReplace(repDecl(3)[:groupHelloLen-1]); ok {
		t.Fatal("a 19-byte packet read as a replacement")
	}
	if _, ok := isGroupReplace(append(repDecl(3), 0)); ok {
		t.Fatal("a 21-byte packet read as a replacement")
	}
	for i := 0; i < 4; i++ {
		bad := repDecl(3)
		bad[i] ^= 0x01
		if _, ok := isGroupReplace(bad); ok {
			t.Fatalf("magic byte %d not checked", i)
		}
	}
	for name, other := range map[string][]byte{"hello": hello(0x7a), "pace": paceDecl(5)} {
		if _, ok := isGroupReplace(other); ok {
			t.Fatalf("a %s sentinel read as a replacement", name)
		}
	}
	if idx, ok := isGroupReplace(repDecl(0x1234)); !ok || idx != 0x1234 {
		t.Fatalf("got %d %v, want 0x1234 (big-endian)", idx, ok)
	}
}

// pumped is one connection through pumpBidirectional against a fake WireGuard
// side; the payload behind its sentinels is read there, so the sentinels are
// known consumed by the time it returns.
type pumped struct {
	c    *scriptedConn
	done chan struct{}
	st   *connStat
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
	n, _, err := wgSide.ReadFromUDP(buf)
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
	return &pumped{c: c, done: done, st: st}
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
	a := runPumped(t, ctx, wgSide, 'a', hello(0x7b), repDecl(3))
	// The successor of the client's connection 3: the predecessor ends at once.
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7b), repDecl(3))
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
	c := runPumped(t, ctx, wgSide, 'c', hello(0x7b), repDecl(4))
	if pumpEnded(b, 300*time.Millisecond) {
		t.Fatalf("a replacement of another index ended member b (reap reason %d)", b.st.reaped.Load())
	}
	if pumpEnded(c, 100*time.Millisecond) {
		t.Fatalf("the member that replaced another index ended itself (reap reason %d)", c.st.reaped.Load())
	}
	// A repeat of the same word from the same connection (every tick's ping): a no-op.
	d := runPumped(t, ctx, wgSide, 'd', hello(0x7b), repDecl(5), repDecl(5), repDecl(5))
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
	a := runPumped(t, ctx, wgSide, 'a', hello(0x7c), repDecl(6))
	a.c.Close()
	if !pumpEnded(a, 3*time.Second) {
		t.Fatal("the fixture: the closed connection's pump did not return")
	}
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7c), repDecl(6))
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
	a := runPumped(t, ctx, wgSide, 'a', repDecl(7), hello(0x7d))
	b := runPumped(t, ctx, wgSide, 'b', hello(0x7d), repDecl(7))
	if pumpEnded(a, 300*time.Millisecond) {
		t.Fatal("a replacement sent before the hello claimed the index")
	}
	c := runPumped(t, ctx, wgSide, 'c', hello(0x7d), repDecl(7))
	if !pumpEnded(b, 3*time.Second) || pumpEnded(a, 100*time.Millisecond) || pumpEnded(c, 100*time.Millisecond) {
		t.Fatal("the claim after the hello did not end its predecessor alone")
	}
	if got := reapsByReason[reapReplaced].Load() - replacedBefore; got != 1 {
		t.Fatalf("replaced counter moved by %d, want 1", got)
	}
}
