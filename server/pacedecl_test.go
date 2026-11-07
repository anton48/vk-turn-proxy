package main

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// 2026-11-07, the user's design: the client DECLARES the pace of a
// connection's relay — 0xff 'P' 'A' 'C' + the rate in KiB/s (two big-endian
// bytes; 0 = no pacer), zero-padded to the hello's 20 bytes, right behind the
// hello — and this server paces that connection's downlink at the declared
// rate instead of -downlink-pace, under -downlink-pace-max. Why the client's
// word: the server sees the address a connection comes from and nothing of
// the relay behind it; the client knows which relay each connection rides
// (its override list's host:port:quota:pace), and a wrong word costs the
// declaring client alone (a VK relay declared unpaced loses ~10 % to VK's
// policer — its loss, nobody else's). The pacer protects the client from VK,
// not the server from the client.

func paceDecl(kib uint16) []byte {
	b := make([]byte, groupHelloLen)
	copy(b, groupPaceMagic)
	binary.BigEndian.PutUint16(b[4:], kib)
	return b
}

func TestIsGroupPace(t *testing.T) {
	if kib, ok := isGroupPace(paceDecl(500)); !ok || kib != 500 {
		t.Fatalf("a declaration of 500 read as %d %v", kib, ok)
	}
	if kib, ok := isGroupPace(paceDecl(0)); !ok || kib != 0 {
		t.Fatalf("a declaration of no pacer read as %d %v", kib, ok)
	}
	probe := []byte{0xff, 'P', 'N', 'G', 0, 0, 0, 0, 0, 0, 0, 1}
	for name, buf := range map[string][]byte{
		"a hello":            hello(0x11),
		"a supersede":        append(append([]byte(nil), groupSupersedeMagic...), make([]byte, 16)...),
		"a probe":            probe,
		"the third byte off": append([]byte{0xff, 'P', 'N', 'C'}, make([]byte, 16)...),
		"short":              paceDecl(500)[:19],
		"long":               append(paceDecl(500), 0),
		"a WireGuard packet": {4, 0, 0, 0, 'd', 'a', 't', 'a'},
		"empty":              nil,
	} {
		if _, ok := isGroupPace(buf); ok {
			t.Errorf("%s read as a pace declaration", name)
		}
	}
}

// The rate a connection paces at: declared, or the flag's; the cap bounds a
// declaration from above and turns "no pacer" into the cap.
func TestADeclaredPaceReplacesTheConnectionsRate(t *testing.T) {
	prevRate, prevBurst, prevMax := downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax
	defer func() { downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax = prevRate, prevBurst, prevMax }()
	downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax = 247<<10, 16<<10, 0

	st := &connStat{}
	if r, b, _ := st.paceRate(); r != 247<<10 || b != 16<<10 {
		t.Fatalf("undeclared: %v %v, want the flag's 247 KiB/s and its burst", r, b)
	}
	if !st.declarePace(500) {
		t.Fatal("the first declaration is not a change")
	}
	if st.declarePace(500) {
		t.Fatal("the same declaration again is a change")
	}
	if r, b, _ := st.paceRate(); r != 500<<10 || b != 16<<10 {
		t.Fatalf("declared 500: %v %v, want 500 KiB/s and the flag's burst", r, b)
	}
	if kib, ok := st.declaredPace(); !ok || kib != 500 {
		t.Fatalf("declaredPace: %d %v", kib, ok)
	}
	st.declarePace(0)
	if r, _, _ := st.paceRate(); r != 0 {
		t.Fatalf("declared no pacer: rate %v, want 0", r)
	}
	// The generation moves with every change, so serveConn can tell.
	_, _, g0 := st.paceRate()
	st.declarePace(300)
	if _, _, g1 := st.paceRate(); g1 == g0 {
		t.Fatal("a new declaration did not move the generation")
	}

	// The cap: a declaration above it is the cap; "no pacer" is the cap.
	downlinkPaceMax = 300 << 10
	st.declarePace(500)
	if r, _, _ := st.paceRate(); r != 300<<10 {
		t.Fatalf("declared 500 under a cap of 300: %v", r)
	}
	st.declarePace(0)
	if r, _, _ := st.paceRate(); r != 300<<10 {
		t.Fatalf("declared no pacer under a cap of 300: %v, want the cap", r)
	}
	st.declarePace(100)
	if r, _, _ := st.paceRate(); r != 100<<10 {
		t.Fatalf("declared 100 under a cap of 300: %v, want 100", r)
	}
	// The flag OFF: an undeclared connection is unpaced, a declared one paced
	// at its word with the default burst (the flag's burst is 0 then).
	downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax = 0, 0, 0
	und := &connStat{}
	if r, _, _ := und.paceRate(); r != 0 {
		t.Fatalf("the flag off, undeclared: %v", r)
	}
	st.declarePace(250)
	if r, b, _ := st.paceRate(); r != 250<<10 || b < pacerMaxCost {
		t.Fatalf("the flag off, declared 250: %v %v, want 250 KiB/s and a burst that holds a packet", r, b)
	}
}

// The declaration is consumed on the inbound path — never forwarded to
// WireGuard — and lands on the connection's record.
func TestTheDeclarationIsConsumedAndReachesTheConnection(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := []byte{4, 0, 0, 0, 'd', 'a', 't', 'a'}
	c := newScriptedConn(hello(0x7a), paceDecl(500), payload)
	before := registry.ids()
	done := make(chan struct{})
	go func() { defer close(done); pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false) }()
	// The pump's writer reads the pacing globals the next test sets: this
	// test leaves only once the pump has returned.
	defer func() { cancel(); c.Close(); <-done }()

	_ = wgSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1600)
	n, _, err := wgSide.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("WireGuard side received nothing: %v", err)
	}
	if _, isPace := isGroupPace(buf[:n]); isPace {
		t.Fatal("the declaration was forwarded to WireGuard instead of being consumed")
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("WireGuard got %q, want the data packet %q", buf[:n], payload)
	}
	var st *connStat
	for id := range registry.ids() {
		if before[id] {
			continue
		}
		st = registry.get(id)
	}
	if st == nil {
		t.Fatal("the pump's connection is not in the registry")
	}
	if kib, ok := st.declaredPace(); !ok || kib != 500 {
		t.Fatalf("the connection's declared pace: %d %v, want 500", kib, ok)
	}
}

// serveConn paces at the declared rate, and picks a declaration up while it
// runs: two consumers under a flag rate too slow to carry the traffic, one
// declares "no pacer" mid-run and drains the queue; the other stays at the
// flag's crawl.
func TestServeConnHonoursTheDeclaredPace(t *testing.T) {
	prevRate, prevBurst, prevMax := downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax
	downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax = 2<<10, pacerMaxCost, 0 // 2 KiB/s: ~1 packet a second
	defer func() { downlinkPaceRate, downlinkPaceBurst, downlinkPaceMax = prevRate, prevBurst, prevMax }()

	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub, err := newDownlinkHub(ctx, wgSide.LocalAddr().String(), "test")
	if err != nil {
		t.Fatalf("newDownlinkHub: %v", err)
	}
	hubAddr := hub.wg.LocalAddr().(*net.UDPAddr)

	paced, free := &fakeConn{}, &fakeConn{}
	pacedSt, freeSt := &connStat{}, &connStat{}
	var wg sync.WaitGroup
	for _, cs := range []struct {
		c  *fakeConn
		st *connStat
	}{{paced, pacedSt}, {free, freeSt}} {
		wg.Add(1)
		go func(c *fakeConn, s *connStat) {
			defer wg.Done()
			hub.serveConn(ctx, c, s)
		}(cs.c, cs.st)
	}
	payload := make([]byte, 512)
	send := func(n int) {
		for i := 0; i < n; i++ {
			binary.BigEndian.PutUint32(payload[:4], uint32(i))
			if _, err := wgSide.WriteToUDP(payload, hubAddr); err != nil {
				t.Fatalf("write: %v", err)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}
	// Both at the crawl: a burst's worth each, the rest queued.
	send(20)
	time.Sleep(300 * time.Millisecond)
	if n := paced.count() + free.count(); n > 6 {
		t.Fatalf("at 2 KiB/s both consumers took %d of 20 packets in 300 ms — the flag's pace is not applied", n)
	}
	// The second declares no pacer: it drains what is queued and what follows.
	freeSt.declarePace(0)
	send(20)
	deadline := time.Now().Add(2 * time.Second)
	for free.count() < 30 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if free.count() < 30 {
		t.Fatalf("the consumer that declared no pacer took %d of 40 — the declaration did not reach serveConn", free.count())
	}
	if paced.count() > 8 {
		t.Fatalf("the undeclared consumer took %d — it is no longer at the flag's pace", paced.count())
	}
	cancel()
	wg.Wait()
}

// Test helpers on the registry: the connections it holds, and one by id.
func (r *connRegistry) ids() map[int]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := map[int]bool{}
	for id := range r.conns {
		m[id] = true
	}
	return m
}

func (r *connRegistry) get(id int) *connStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[id]
}
