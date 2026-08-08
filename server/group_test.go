package main

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// The reaper's timings are package globals written once in main() before any
// goroutine starts, then read-only — the same contract as connStatsInterval and
// the pacer settings. Tests must honour that contract: shrinking them per-test
// races against pumps still winding down from the previous test. Set them ONCE
// here, before any test runs, and never touch them again.
//
// 800 ms is chosen to be far longer than any test's settle window (150-400 ms)
// so only the test that deliberately goes silent gets reaped.
func TestMain(m *testing.M) {
	groupIdleTimeout = 800 * time.Millisecond
	groupReapEvery = 50 * time.Millisecond
	os.Exit(m.Run())
}

// scriptedConn plays a fixed sequence of inbound packets, then blocks until
// closed. Writes are recorded. It stands in for a relay connection.
type scriptedConn struct {
	mu     sync.Mutex
	in     [][]byte
	got    [][]byte
	closed chan struct{}
	once   sync.Once
}

func newScriptedConn(pkts ...[]byte) *scriptedConn {
	return &scriptedConn{in: pkts, closed: make(chan struct{})}
}

func (s *scriptedConn) Read(b []byte) (int, error) {
	s.mu.Lock()
	if len(s.in) > 0 {
		p := s.in[0]
		s.in = s.in[1:]
		s.mu.Unlock()
		return copy(b, p), nil
	}
	s.mu.Unlock()
	<-s.closed
	return 0, net.ErrClosed
}
func (s *scriptedConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	s.got = append(s.got, append([]byte(nil), b...))
	s.mu.Unlock()
	return len(b), nil
}
func (s *scriptedConn) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}
func (s *scriptedConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (s *scriptedConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (s *scriptedConn) SetDeadline(time.Time) error      { s.Close(); return nil }
func (s *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func hello(id byte) []byte {
	p := append([]byte(nil), groupHelloMagic...)
	for i := 0; i < groupIDLen; i++ {
		p = append(p, id)
	}
	return p
}

// The hello has to be recognised exactly, and — more importantly — nothing else
// may be mistaken for one. A false positive would swallow a WireGuard packet.
func TestIsGroupHello(t *testing.T) {
	k, ok := isGroupHello(hello(0xab))
	if !ok {
		t.Fatal("a well-formed hello was not recognised")
	}
	for _, b := range k {
		if b != 0xab {
			t.Fatalf("session id mis-parsed: %x", k)
		}
	}

	for name, pkt := range map[string][]byte{
		"probe ping":        {0xff, 'P', 'N', 'G', 0, 0, 0, 0, 0, 0, 0, 1},
		"magic but short":   append(append([]byte(nil), groupHelloMagic...), 1, 2, 3),
		"magic but long":    append(hello(1), 0),
		"right length, wg":  make([]byte, groupHelloLen),
		"empty":             {},
		"prefix only":       groupHelloMagic,
		"wrong third byte":  {0xff, 'G', 'X', 'P', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		"not 0xff-prefixed": {0x04, 'G', 'R', 'P', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	} {
		if _, ok := isGroupHello(pkt); ok {
			t.Fatalf("%s was mistaken for a group hello", name)
		}
	}
}

// The registry must hand the same hub to the same group and a different one to
// a different group — that IS the fix — and must close a hub when its last
// connection leaves, or a departed client leaves WireGuard pointed at a socket
// nobody reads.
func TestHubRegistryLifetime(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()
	target := wgSide.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &hubRegistry{hubs: make(map[groupKey]*hubEntry)}
	a1, err := r.acquire(ctx, target, groupKey{1})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	a2, err := r.acquire(ctx, target, groupKey{1})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if a1 != a2 {
		t.Fatal("same group got two different hubs — the whole point is one socket per client")
	}
	b1, err := r.acquire(ctx, target, groupKey{2})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if b1 == a1 {
		t.Fatal("two different groups share a hub — one client's downlink would be sprayed into the other's connections")
	}

	r.release(groupKey{1})
	if len(r.hubs) != 2 {
		t.Fatalf("hub dropped while a connection still held it: %d groups", len(r.hubs))
	}
	r.release(groupKey{1})
	r.release(groupKey{2})
	if len(r.hubs) != 0 {
		t.Fatalf("hubs leaked after the last release: %d left", len(r.hubs))
	}
	// Releasing an unknown key must not panic or corrupt the map.
	r.release(groupKey{9})
}

// pumpTest runs pumpBidirectional against a scripted connection and reports
// which group, if any, it ended up in.
func pumpTest(t *testing.T, pkts [][]byte, singleClient bool, settle time.Duration) (*scriptedConn, func()) {
	t.Helper()
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := newScriptedConn(pkts...)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), singleClient)
	}()
	time.Sleep(settle)
	return c, func() {
		cancel()
		c.Close()
		<-done
		wgSide.Close()
	}
}

func groupCount() int {
	groups.mu.Lock()
	defer groups.mu.Unlock()
	return len(groups.hubs)
}

func hasGroup(k groupKey) bool {
	groups.mu.Lock()
	defer groups.mu.Unlock()
	_, ok := groups.hubs[k]
	return ok
}

// The three compatibility cases, end to end.
func TestPromotionByHello(t *testing.T) {
	if groupCount() != 0 {
		t.Fatalf("test started with %d groups already registered", groupCount())
	}

	t.Run("a client that sends no hello never joins a group", func(t *testing.T) {
		// This is the old-client case, and it is the one that must not regress:
		// the server must never wait for a hello, because it will never come.
		_, stop := pumpTest(t, [][]byte{{4, 0, 0, 0, 1, 2, 3}}, false, 150*time.Millisecond)
		defer stop()
		if groupCount() != 0 {
			t.Fatalf("an ungrouped connection created %d group(s)", groupCount())
		}
	})

	t.Run("a hello promotes the connection into its group", func(t *testing.T) {
		key := groupKey{}
		for i := range key {
			key[i] = 0x11
		}
		_, stop := pumpTest(t, [][]byte{hello(0x11)}, false, 150*time.Millisecond)
		defer stop()
		if !hasGroup(key) {
			t.Fatal("the hello did not create its group")
		}
	})

	t.Run("two session ids get two hubs", func(t *testing.T) {
		_, stopA := pumpTest(t, [][]byte{hello(0x22)}, false, 100*time.Millisecond)
		defer stopA()
		_, stopB := pumpTest(t, [][]byte{hello(0x33)}, false, 150*time.Millisecond)
		defer stopB()
		if n := groupCount(); n != 2 {
			t.Fatalf("two clients produced %d group(s), want 2 — with one hub "+
				"between them each client's WireGuard would reject the other's traffic", n)
		}
	})

	t.Run("the same session id shares one hub", func(t *testing.T) {
		_, stopA := pumpTest(t, [][]byte{hello(0x44)}, false, 100*time.Millisecond)
		defer stopA()
		_, stopB := pumpTest(t, [][]byte{hello(0x44)}, false, 150*time.Millisecond)
		defer stopB()
		if n := groupCount(); n != 1 {
			t.Fatalf("two connections of ONE client produced %d group(s), want 1", n)
		}
	})

	// Groups must not outlive their connections.
	deadline := time.Now().Add(2 * time.Second)
	for groupCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := groupCount(); n != 0 {
		t.Fatalf("%d group(s) leaked after every connection closed", n)
	}
}

// A hello must be consumed, never forwarded: WireGuard would drop it anyway, but
// forwarding would also mean the sentinel reached a layer that never asked for
// it. Verified by watching what the WireGuard side actually receives.
func TestHelloIsNotForwardedToWireGuard(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := []byte{4, 0, 0, 0, 'd', 'a', 't', 'a'}
	c := newScriptedConn(hello(0x55), payload)
	go pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false)
	defer c.Close()

	_ = wgSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1600)
	n, _, err := wgSide.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("WireGuard side received nothing: %v", err)
	}
	if _, isHello := isGroupHello(buf[:n]); isHello {
		t.Fatal("the hello was forwarded to WireGuard instead of being consumed")
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("WireGuard got %q, want the data packet %q", buf[:n], payload)
	}
}

// The reaper exists for one specific failure: a connection whose client is gone
// but whose writes still succeed keeps stealing from the group's shared queue.
// An ungrouped connection has no such queue and must be left alone.
func TestIdleReaperOnlyTouchesGroupedConns(t *testing.T) {
	t.Run("grouped and silent is reaped", func(t *testing.T) {
		wgSide, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		defer wgSide.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := newScriptedConn(hello(0x66))
		done := make(chan struct{})
		go func() { defer close(done); pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("a silent grouped connection was not reaped — it would keep " +
				"stealing downlink and dropping it")
		}
	})

	t.Run("ungrouped and silent is left alone", func(t *testing.T) {
		wgSide, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		defer wgSide.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := newScriptedConn()
		done := make(chan struct{})
		go func() { defer close(done); pumpBidirectional(ctx, c, wgSide.LocalAddr().String(), false) }()
		select {
		case <-done:
			t.Fatal("an ungrouped connection was reaped; it harms nobody and " +
				"killing it would break long-idle old clients")
		case <-time.After(400 * time.Millisecond):
		}
		cancel()
		c.Close()
		<-done
	})
}

// THE TEST M3 EXISTS FOR. Two clients, two groups, one WireGuard behind them.
// Every packet WireGuard sends toward group A's socket must reach ONLY group A's
// connections — if any of it lands on a group B connection, B's WireGuard drops
// it on the keypair and both clients lose throughput. That is precisely the
// failure that kept -single-client an experiment flag.
func TestTwoClientsDoNotCrossDeliver(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()
	target := wgSide.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const perClient = 3
	keyA, keyB := groupKey{}, groupKey{}
	for i := range keyA {
		keyA[i], keyB[i] = 0xaa, 0xbb
	}

	start := func(h []byte) []*scriptedConn {
		conns := make([]*scriptedConn, perClient)
		for i := range conns {
			conns[i] = newScriptedConn(h)
			go pumpBidirectional(ctx, conns[i], target, false)
		}
		return conns
	}
	connsA, connsB := start(hello(0xaa)), start(hello(0xbb))
	defer func() {
		for _, c := range append(append([]*scriptedConn{}, connsA...), connsB...) {
			c.Close()
		}
	}()

	// Wait for both groups to exist before addressing their sockets.
	deadline := time.Now().Add(3 * time.Second)
	for (!hasGroup(keyA) || !hasGroup(keyB)) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !hasGroup(keyA) || !hasGroup(keyB) {
		t.Fatal("the two clients did not form two groups")
	}

	groups.mu.Lock()
	addrA := groups.hubs[keyA].hub.wg.LocalAddr().String()
	addrB := groups.hubs[keyB].hub.wg.LocalAddr().String()
	groups.mu.Unlock()
	if addrA == addrB {
		t.Fatal("both groups are using ONE socket toward WireGuard — with two " +
			"clients that is the bug M3 exists to prevent")
	}

	// WireGuard now replies to each group on its own socket, as it would with
	// one endpoint per peer.
	const each = 90
	send := func(addr, tag string) {
		ua, _ := net.ResolveUDPAddr("udp", addr)
		for i := 0; i < each; i++ {
			if _, err := wgSide.WriteToUDP([]byte(tag), ua); err != nil {
				t.Errorf("write to %s: %v", addr, err)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	send(addrA, "A")
	send(addrB, "B")

	// Give the writers a moment to drain.
	time.Sleep(500 * time.Millisecond)

	tally := func(conns []*scriptedConn, mine string) (own, foreign int) {
		for _, c := range conns {
			c.mu.Lock()
			for _, p := range c.got {
				if string(p) == mine {
					own++
				} else {
					foreign++
				}
			}
			c.mu.Unlock()
		}
		return own, foreign
	}
	aOwn, aForeign := tally(connsA, "A")
	bOwn, bForeign := tally(connsB, "B")

	if aForeign != 0 || bForeign != 0 {
		t.Fatalf("CROSS-DELIVERY: client A received %d of B's packets, client B "+
			"received %d of A's. Each client's WireGuard rejects the other's "+
			"traffic on the keypair, so this is silent, total loss of whatever "+
			"crossed.", aForeign, bForeign)
	}
	if aOwn != each || bOwn != each {
		t.Fatalf("packets lost inside a group: A got %d/%d, B got %d/%d", aOwn, each, bOwn, each)
	}
}
