package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The pacer's whole job is a long-run RATE, so that is what the test asserts:
// drain a bucket at a known rate and check the elapsed time, not the token
// bookkeeping. Rates here are deliberately large so the test runs in
// milliseconds while still crossing many refill intervals.
func TestPacerHoldsItsLongRunRate(t *testing.T) {
	const rate = 1 << 20 // 1 MiB/s of counted bytes
	const burst = 4096
	const cost = 1024
	const packets = 300

	p := newPacer(rate, burst)
	start := time.Now()
	for i := 0; i < packets; i++ {
		if wait := p.take(cost); wait > 0 {
			time.Sleep(wait)
		}
	}
	elapsed := time.Since(start)

	// packets*cost bytes at rate bytes/s, minus the initial full bucket.
	want := time.Duration(float64(packets*cost-burst) / rate * float64(time.Second))
	if elapsed < want*9/10 {
		t.Fatalf("drained %d B in %s, faster than the %s the rate allows — "+
			"the pacer is not limiting", packets*cost, elapsed, want)
	}
	if elapsed > want*3/2 {
		t.Fatalf("drained %d B in %s, want ~%s — the pacer is over-throttling", packets*cost, elapsed, want)
	}
}

// A token bucket that let debt accumulate without bound, or that refilled past
// its ceiling, would emit exactly the bursts this milestone exists to remove.
func TestPacerBurstIsBounded(t *testing.T) {
	const rate, burst = 1000, 5000
	p := newPacer(rate, burst)

	// Idle far longer than it takes to fill, then check that only `burst` is
	// available instantly.
	p.mu.Lock()
	p.last = time.Now().Add(-time.Hour)
	p.mu.Unlock()

	if wait := p.take(burst); wait != 0 {
		t.Fatalf("a full bucket must serve %d B immediately, waited %s", burst, wait)
	}
	if wait := p.take(1); wait <= 0 {
		t.Fatalf("bucket should be empty after draining it; got no wait for the next byte")
	}
}

// refund exists so that reserving for a maximum-size packet and then sending a
// small one does not silently throttle the connection to the max-size rate.
func TestPacerRefundReturnsUnusedReservation(t *testing.T) {
	const rate, burst = 1000, 10000
	p := newPacer(rate, burst)

	p.take(8000)
	p.refund(7000)
	// 10000 - 8000 + 7000 = 9000, clamped by nothing; a 9000-byte take must
	// still be free.
	if wait := p.take(9000); wait != 0 {
		t.Fatalf("refunded tokens were lost: waited %s for a send the bucket could afford", wait)
	}

	// And it must never exceed the ceiling.
	p2 := newPacer(rate, burst)
	p2.refund(1e9)
	p2.mu.Lock()
	tok := p2.tokens
	p2.mu.Unlock()
	if tok > burst {
		t.Fatalf("refund overfilled the bucket: %v tokens against a %d ceiling", tok, burst)
	}
}

// A cancelled context must abort the wait rather than sleep it out, or every
// connection teardown would block for the full token debt.
func TestPacerAwaitHonoursContext(t *testing.T) {
	p := newPacer(1, 1) // 1 B/s: any real reservation waits a very long time
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, ok := p.await(ctx, 10_000); ok {
		t.Fatal("await reported success on a cancelled context — the caller would send anyway")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("await slept %s instead of returning on cancellation", el)
	}
}

// The 'pacer:' line is the only thing that will tell us, from a production log,
// whether a run actually exercised the shaper — so its arithmetic and its
// on/off condition both need pinning.
func TestPacerSummaryLine(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()

	prevRate := downlinkPaceRate
	defer func() { downlinkPaceRate = prevRate }()

	reg := &connRegistry{
		conns:      make(map[int]*connStat),
		prevUp:     make(map[int]int64),
		prevDn:     make(map[int]int64),
		prevDnPkts: make(map[int]int64),
		prevPaced:  make(map[int]int64),
		prevPaceNs: make(map[int]int64),
	}
	c := reg.add("1.2.3.4:5")
	c.down.Add(1000)
	c.downPkts.Add(200)
	c.pacedPkts.Add(50)
	c.pacedNs.Add(int64(500 * time.Millisecond))

	// Off: the line must not appear at all, or every unpaced log gains a
	// permanently-zero row that reads like a failure.
	downlinkPaceRate = 0
	reg.dump(time.Second, "tick")
	if strings.Contains(buf.String(), "pacer:") {
		t.Fatalf("pacer line printed while pacing is off:\n%s", buf.String())
	}

	// On: 50 of 200 delayed = 25.0%, mean wait 500ms/50 = 10ms.
	buf.Reset()
	downlinkPaceRate = 1
	c.downPkts.Add(200)
	c.pacedPkts.Add(50)
	c.pacedNs.Add(int64(500 * time.Millisecond))
	reg.dump(time.Second, "tick")
	out := buf.String()
	if !strings.Contains(out, "pacer: 50/200 writes delayed (25.0%)") {
		t.Fatalf("pacer counts or percentage wrong:\n%s", out)
	}
	if !strings.Contains(out, "Σwait 500ms") || !strings.Contains(out, "mean wait 10ms") {
		t.Fatalf("pacer wait arithmetic wrong:\n%s", out)
	}
}

// The unit label has to match the divisor. It did not, once, and two analyses
// of the same log then disagreed by 4.7% over nothing.
func TestHumanBytesLabelsBinaryUnits(t *testing.T) {
	if got := humanBytes(1 << 20); got != "1.0 MiB" {
		t.Fatalf("humanBytes(1MiB) = %q, want 1.0 MiB", got)
	}
	if got := humanBytes(1 << 10); got != "1.0 KiB" {
		t.Fatalf("humanBytes(1KiB) = %q, want 1.0 KiB", got)
	}
	if got := humanBytes(999); got != "999 B" {
		t.Fatalf("humanBytes(999) = %q, want 999 B", got)
	}
}

// The pacer sits on the hub's hot path, so the conservation guarantee that
// TestDownlinkHubConservesAndDoesNotCorrupt establishes must survive it: every
// packet exactly once, intact, and still fanned out across connections rather
// than serialised behind one paced writer.
func TestDownlinkHubWithPacerStillConservesAndFansOut(t *testing.T) {
	prevRate, prevBurst := downlinkPaceRate, downlinkPaceBurst
	// Well under what the producer below offers each connection, so writes
	// really do wait; still fast enough that the test finishes in a moment.
	downlinkPaceRate, downlinkPaceBurst = 128<<10, pacerMaxCost*2
	defer func() { downlinkPaceRate, downlinkPaceBurst = prevRate, prevBurst }()

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

	const consumers, packets = 4, 200
	conns := make([]*fakeConn, consumers)
	stats := make([]*connStat, consumers)
	var wg sync.WaitGroup
	for i := range conns {
		conns[i] = &fakeConn{}
		stats[i] = &connStat{}
		wg.Add(1)
		go func(c *fakeConn, s *connStat) {
			defer wg.Done()
			hub.serveConn(ctx, c, s)
		}(conns[i], stats[i])
	}

	payload := make([]byte, 512)
	for i := 0; i < packets; i++ {
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		if _, err := wgSide.WriteToUDP(payload, hubAddr); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		// Pace the producer a little; a UDP socket buffer will otherwise drop
		// what the paced consumers cannot take, and this test is about the
		// hub's conservation, not the kernel's.
		time.Sleep(200 * time.Microsecond)
	}

	total := func() int {
		n := 0
		for _, c := range conns {
			n += c.count()
		}
		return n
	}
	deadline := time.Now().Add(10 * time.Second)
	for total() < packets && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	wg.Wait()

	if got := total(); got != packets {
		t.Fatalf("delivered %d of %d packets with pacing on", got, packets)
	}
	seen := make(map[uint32]int)
	for _, c := range conns {
		for _, p := range c.got {
			if len(p) != len(payload) {
				t.Fatalf("packet truncated under pacing: %d bytes, want %d", len(p), len(payload))
			}
			seen[binary.BigEndian.Uint32(p[:4])]++
		}
	}
	for i := 0; i < packets; i++ {
		if n := seen[uint32(i)]; n != 1 {
			t.Fatalf("packet %d arrived %d times under pacing", i, n)
		}
	}

	used := 0
	for _, c := range conns {
		if c.count() > 0 {
			used++
		}
	}
	if used < 2 {
		t.Fatalf("pacing serialised the downlink onto %d connection(s) — "+
			"the reservation must be taken BEFORE dequeuing, or a waiting "+
			"writer pins packets that a free writer could send", used)
	}

	// The instrumentation is how we will read the production run, so it has to
	// have counted something.
	var pkts, paced int64
	for _, s := range stats {
		pkts += s.downPkts.Load()
		paced += s.pacedPkts.Load()
	}
	if pkts != packets {
		t.Fatalf("downPkts counted %d writes, want %d", pkts, packets)
	}
	if paced == 0 {
		t.Fatal("no write was ever delayed, so this run did not exercise the pacer")
	}
	// The first production run printed "8024/7999 writes delayed (100.3%)"
	// because the wait was counted at reservation time and the write after it,
	// so a dump could land between them. The two must be charged together.
	if paced > pkts {
		t.Fatalf("%d delayed of %d written — the delay counter is charged "+
			"before the write and can exceed it", paced, pkts)
	}
}
