package main

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeConn is a net.Conn that only records what was written to it.
type fakeConn struct {
	mu   sync.Mutex
	got  [][]byte
	slow time.Duration
}

func (f *fakeConn) Write(b []byte) (int, error) {
	if f.slow > 0 {
		time.Sleep(f.slow)
	}
	cp := append([]byte(nil), b...)
	f.mu.Lock()
	f.got = append(f.got, cp)
	f.mu.Unlock()
	return len(b), nil
}
func (f *fakeConn) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}
func (f *fakeConn) Read([]byte) (int, error)         { select {} }
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// The hub recycles packet buffers through a sync.Pool, so the one failure that
// would silently corrupt a tunnel is a buffer handed back while a writer is
// still using it. Send distinctly-numbered packets through several consumers
// and require every one to arrive intact and exactly once.
func TestDownlinkHubConservesAndDoesNotCorrupt(t *testing.T) {
	wgSide, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer wgSide.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub, err := newDownlinkHub(ctx, wgSide.LocalAddr().String())
	if err != nil {
		t.Fatalf("newDownlinkHub: %v", err)
	}
	hubAddr := hub.wg.LocalAddr().(*net.UDPAddr)

	const consumers, packets = 4, 400
	conns := make([]*fakeConn, consumers)
	var wg sync.WaitGroup
	for i := range conns {
		conns[i] = &fakeConn{slow: 50 * time.Microsecond}
		st := &connStat{}
		wg.Add(1)
		go func(c *fakeConn, s *connStat) {
			defer wg.Done()
			hub.serveConn(ctx, c, s)
		}(conns[i], st)
	}

	payload := make([]byte, 64)
	for i := 0; i < packets; i++ {
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		if _, err := wgSide.WriteToUDP(payload, hubAddr); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Drain, then stop the consumers.
	deadline := time.Now().Add(5 * time.Second)
	total := func() int {
		n := 0
		for _, c := range conns {
			n += c.count()
		}
		return n
	}
	for total() < packets && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	if got := total(); got != packets {
		t.Fatalf("delivered %d of %d packets — the hub is losing or duplicating", got, packets)
	}

	seen := make(map[uint32]int)
	for _, c := range conns {
		for _, p := range c.got {
			if len(p) != len(payload) {
				t.Fatalf("packet truncated: got %d bytes, want %d", len(p), len(payload))
			}
			seen[binary.BigEndian.Uint32(p[:4])]++
		}
	}
	for i := 0; i < packets; i++ {
		switch n := seen[uint32(i)]; {
		case n == 0:
			t.Fatalf("packet %d never arrived", i)
		case n > 1:
			t.Fatalf("packet %d arrived %d times — buffer reused while in flight", i, n)
		}
	}

	// Fan-out must actually happen: the entire point is that no single
	// connection carries the whole downlink.
	used := 0
	for _, c := range conns {
		if c.count() > 0 {
			used++
		}
	}
	if used < 2 {
		t.Fatalf("only %d of %d connections carried traffic — no fan-out", used, consumers)
	}
}

// The summary line is what we read to decide whether the fix worked, so its
// two derived numbers have to be right.
func TestConnStatsSummaryMath(t *testing.T) {
	if got := ratio(100, 25); got != "4.00x" {
		t.Fatalf("ratio(100,25) = %s, want 4.00x", got)
	}
	if got := ratio(100, 0); got != "n/a" {
		t.Fatalf("ratio with an idle connection must not divide by zero, got %s", got)
	}
	if got := share(20, 200); got != "10.00%" {
		t.Fatalf("share(20,200) = %s, want 10.00%%", got)
	}
	if got := share(5, 0); got != "n/a" {
		t.Fatalf("share of an empty interval must be n/a, got %s", got)
	}
}
