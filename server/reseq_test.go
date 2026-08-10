package main

import (
	"log"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder captures the order in which packets reach WireGuard.
type recorder struct {
	mu   sync.Mutex
	ctrs []uint64
	raw  int // writes that carried no counter (handshakes)
}

func (w *recorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) >= wgTransportHdrLen && p[0] == wgMsgTypeTransport {
		w.ctrs = append(w.ctrs, uint64(p[8])|uint64(p[9])<<8|uint64(p[10])<<16|uint64(p[11])<<24)
	} else {
		w.raw++
	}
	return len(p), nil
}

func (w *recorder) seen() []uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]uint64, len(w.ctrs))
	copy(out, w.ctrs)
	return out
}

func newReseq(t *testing.T, hold time.Duration) (*resequencer, *recorder) {
	t.Helper()
	w := &recorder{}
	r := newResequencer(w, "test", hold)
	// Stop the timer goroutine before the test ends, or it outlives the test and
	// keeps writing counters the assertions read.
	t.Cleanup(r.close)
	return r, w
}

func inversions(s []uint64) int {
	n := 0
	for i := 1; i < len(s); i++ {
		if s[i] < s[i-1] {
			n++
		}
	}
	return n
}

// An already-ordered stream must pass through untouched and buffer nothing.
// If it cannot do that, every other reading from this thing is meaningless.
func TestInOrderStreamIsNotBuffered(t *testing.T) {
	r, w := newReseq(t, 50*time.Millisecond)
	for i := uint64(0); i < 500; i++ {
		if err := r.write(wgPkt(1, i)); err != nil {
			t.Fatal(err)
		}
	}
	if r.buffered != 0 {
		t.Fatalf("buffered = %d on an ordered stream, want 0", r.buffered)
	}
	if got := len(w.seen()); got != 500 {
		t.Fatalf("wrote %d packets, want 500", got)
	}
	if n := inversions(w.seen()); n != 0 {
		t.Fatalf("%d inversions on an ordered stream", n)
	}
}

// 🎯 THE PROPERTY THE WHOLE CHANGE EXISTS FOR. A stream shuffled the way the
// client's fan-out shuffles it — displaced by up to ~N/2, arriving within a few
// milliseconds — must come out in order, and nothing may be lost.
func TestShuffledStreamComesOutInOrder(t *testing.T) {
	r, w := newReseq(t, 200*time.Millisecond)
	const n = 2000
	const window = 15 // the depth a spread of path latencies produces
	rng := rand.New(rand.NewSource(1))

	// Emit in order but deliver from a small reorder window, which is what a
	// spread of path latencies produces.
	pending := []uint64{}
	for i := uint64(0); i < n; i++ {
		pending = append(pending, i)
		if len(pending) >= window {
			j := rng.Intn(len(pending))
			if err := r.write(wgPkt(1, pending[j])); err != nil {
				t.Fatal(err)
			}
			pending = append(pending[:j], pending[j+1:]...)
		}
	}
	for _, c := range pending {
		if err := r.write(wgPkt(1, c)); err != nil {
			t.Fatal(err)
		}
	}
	r.close() // flush whatever the window still holds

	got := w.seen()
	if len(got) != n {
		t.Fatalf("wrote %d of %d packets — the resequencer LOST data", len(got), n)
	}
	// ⚠️ State the startup transient EXACTLY rather than skipping the first few
	// outputs. The first packet seen defines where the sequence starts, so
	// counters BELOW it missed their slot and are forwarded out of order by
	// design (see reseq.go). Those packets land at unpredictable output
	// positions, so "ignore the first 15 outputs" is the wrong exclusion — it
	// let one inversion through and the test caught me doing it. The property
	// that actually holds: everything from the sequence start onward is in
	// order, and the bypassed remainder is bounded by the reorder window.
	start := got[0]
	if int(start) >= window {
		t.Fatalf("sequence started at %d, beyond the reorder window", start)
	}
	if r.lateBypass != int64(start) {
		t.Fatalf("lateBypass = %d, want %d — exactly the counters that predate "+
			"the first packet seen", r.lateBypass, start)
	}
	var fromStart []uint64
	for _, c := range got {
		if c >= start {
			fromStart = append(fromStart, c)
		}
	}
	if len(fromStart) != n-int(start) {
		t.Fatalf("kept %d packets from the sequence start, want %d", len(fromStart), n-int(start))
	}
	if inv := inversions(fromStart); inv != 0 {
		t.Fatalf("%d inversions from the sequence start onward; "+
			"the stream is still shuffled", inv)
	}
	if r.buffered == 0 {
		t.Fatal("nothing was buffered — the input was not actually shuffled, so this test proved nothing")
	}
}

// A gap that never fills must not stall the stream. This is the bound that
// makes the change safe to run: the client can die mid-sequence and the rest
// still flows.
func TestUnfilledGapIsReleasedAfterTheHold(t *testing.T) {
	r, w := newReseq(t, 30*time.Millisecond)
	if err := r.write(wgPkt(1, 0)); err != nil {
		t.Fatal(err)
	}
	// 1 is lost forever; 2..5 arrive and must wait, then go.
	for i := uint64(2); i <= 5; i++ {
		if err := r.write(wgPkt(1, i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(w.seen()); got != 1 {
		t.Fatalf("released %d before the hold expired, want 1", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(w.seen()) < 5 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	got := w.seen()
	if len(got) != 5 {
		t.Fatalf("released %d after the hold, want 5 — a gap stalled the stream", len(got))
	}
	if inversions(got) != 0 {
		t.Fatalf("released out of order: %v", got)
	}
	if r.timeouts == 0 {
		t.Fatal("timeouts = 0 — the release happened for some other reason")
	}
}

// 🚨 THE TEST THAT WAS MISSING, and whose absence let a real defect ship.
//
// The bound must be PER PACKET. The first version released one gap per timer
// firing and re-armed, so a packet behind K gaps waited K × holdFor — on the
// device that came out as a mean hold of 98-248 ms under a 30 ms timer. Every
// test I had passed, because every one of them contained a single gap.
func TestHoldIsBoundedPerPacketNotPerGap(t *testing.T) {
	const hold = 50 * time.Millisecond
	const gaps = 8
	r, w := newReseq(t, hold)

	start := time.Now()
	_ = r.write(wgPkt(1, 0)) // released at once
	// Odd counters are lost forever, so every even one sits behind its own gap.
	for i := 1; i <= gaps; i++ {
		_ = r.write(wgPkt(1, uint64(2*i)))
	}
	if got := len(w.seen()); got != 1 {
		t.Fatalf("released %d before the hold expired, want 1", got)
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(w.seen()) < gaps+1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	elapsed := time.Since(start)
	got := w.seen()
	if len(got) != gaps+1 {
		t.Fatalf("released %d of %d packets", len(got), gaps+1)
	}
	// ⚠️ The bound MOVED deliberately on 2026-08-10 and this test moved with it.
	// Giving up a whole gap at once is what manufactured the disorder the
	// resequencer exists to remove, so a hole is now abandoned ONE counter at a
	// time and the per-packet ceiling is the safety valve at
	// reseqMaxWaitFactor × holdFor. What must still hold is that it is BOUNDED
	// and far under the old per-gap behaviour, which needed gaps × hold.
	valve := time.Duration(reseqMaxWaitFactor) * hold
	if limit := valve + 40*time.Millisecond; elapsed > limit {
		t.Fatalf("the last packet behind %d gaps waited %s, want under %s",
			gaps, elapsed.Round(time.Millisecond), limit)
	}
	if perGap := time.Duration(gaps) * hold; elapsed >= perGap {
		t.Fatalf("waited %s, i.e. gaps × hold — the bound is per gap again",
			elapsed.Round(time.Millisecond))
	}
	if inversions(got) != 0 {
		t.Fatalf("released out of order: %v", got)
	}
	if r.valves == 0 {
		t.Fatal("the safety valve never opened, so this did not test it")
	}
}

// A packet whose slot was already released must be FORWARDED, never dropped:
// dropping would manufacture exactly the real loss this change exists to avoid.
func TestLatePacketIsForwardedNotDropped(t *testing.T) {
	r, w := newReseq(t, 10*time.Millisecond)
	_ = r.write(wgPkt(1, 0))
	_ = r.write(wgPkt(1, 2)) // held, waiting for 1
	deadline := time.Now().Add(time.Second)
	for len(w.seen()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	_ = r.write(wgPkt(1, 1)) // arrives after its slot went
	got := w.seen()
	if len(got) != 3 {
		t.Fatalf("wrote %d packets, want 3 — the late one was dropped", len(got))
	}
	if r.lateBypass != 1 {
		t.Fatalf("lateBypass = %d, want 1", r.lateBypass)
	}
}

// Overflow must bound memory without losing anything.
func TestOverflowReleasesWithoutLoss(t *testing.T) {
	r, w := newReseq(t, time.Hour) // the timer must not be what saves us
	_ = r.write(wgPkt(1, 0))
	// 1 never arrives; pile up more than the buffer allows.
	for i := uint64(2); i < uint64(reseqMaxHeld+50); i++ {
		_ = r.write(wgPkt(1, i))
	}
	if r.overflows == 0 {
		t.Fatal("overflows = 0 — the buffer bound never engaged")
	}
	got := w.seen()
	// 1 (counter 0) + (reseqMaxHeld+50-2) more = reseqMaxHeld+49 in, and NOTHING
	// may be dropped, so exactly that many must come out.
	if want := reseqMaxHeld + 49; len(got) != want {
		t.Fatalf("wrote %d packets, want %d — overflow dropped data", len(got), want)
	}
	if inversions(got) != 0 {
		t.Fatal("overflow released out of order")
	}
	r.close()
}

// 🚨 REKEY IS ORDERED, NOT FLUSHED. The sender switches keypairs at an instant,
// so every old-keypair packet precedes every new-keypair one in the inner
// stream. The first version kept ONE current index and reset on every switch,
// which thrashed while 30 connections carried both keypairs — measured on the
// device as a 4.855 s hold against a 150 ms bound and an output displacement of
// p50 1024 / max 5572. Generations fix both the thrash and the ordering: the
// new generation waits until the old one has been quiet for a hold.
func TestRekeyKeepsGenerationsInOrder(t *testing.T) {
	const hold = 40 * time.Millisecond
	r, w := newReseq(t, hold)
	_ = r.write(wgPkt(0xAAAA, 0)) // old keypair, in order → out at once
	_ = r.write(wgPkt(0xAAAA, 2)) // old keypair, held behind the gap at 1
	_ = r.write(wgPkt(0xBBBB, 0)) // NEW keypair — must not overtake the old one
	_ = r.write(wgPkt(0xBBBB, 1))

	if n := len(w.seen()); n != 1 {
		t.Fatalf("released %d immediately, want 1 — the new keypair overtook the old", n)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(w.seen()) < 4 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	got := w.seen()
	if len(got) != 4 {
		t.Fatalf("released %d of 4 — a generation was stranded", len(got))
	}
	// Counters repeat across the rekey, so order is checked by GENERATION:
	// the old keypair's 0 and 2 must both precede the new keypair's 0 and 1.
	if got[0] != 0 || got[1] != 2 || got[2] != 0 || got[3] != 1 {
		t.Fatalf("emitted %v, want old(0,2) then new(0,1)", got)
	}
	if r.rekeys != 1 {
		t.Fatalf("rekeys = %d, want 1", r.rekeys)
	}
}

// 🎯 THE POINT OF THE HOLE DEADLINE, and the test had to be built twice.
//
// The first version expired a HELD PACKET and, to release it, declared every
// counter between `next` and that packet lost in ONE step. With a reorder depth
// of 200-650 that abandoned hundreds of slots whose packets were only ~15 ms
// behind, and they then had to be forwarded out of order — `late-bypass 212`,
// output displacement p50 185, the resequencer manufacturing the disorder it
// exists to remove.
//
// ⚠️ My first attempt at this test could not tell the two apart: the straggler
// arrived before ANY deadline expired, so both versions behaved identically and
// the sabotage passed. The difference only shows when an expiry has already
// happened and a packet then arrives inside the skipped range. Hence the shape
// below: one expiry, then a straggler well above the counter we gave up on.
func TestOneExpiryGivesUpOneCounterNotTheWholeGap(t *testing.T) {
	const hold = 50 * time.Millisecond
	r, w := newReseq(t, hold)
	_ = r.write(wgPkt(1, 0))   // out at once; next = 1
	_ = r.write(wgPkt(1, 200)) // held, far above — the deep-reorder shape

	// One deadline passes: counter 1 is given up on, and ONLY counter 1.
	time.Sleep(hold + 30*time.Millisecond)
	if n := len(w.seen()); n != 1 {
		t.Fatalf("released %d after one expiry, want 1 — the whole gap was abandoned", n)
	}

	// A packet from the middle of the range now arrives. It is not counter 1, so
	// its slot must still be there.
	_ = r.write(wgPkt(1, 5))
	if r.lateBypass != 0 {
		t.Fatalf("lateBypass = %d, want 0 — counter 5 was declared lost along with 1", r.lateBypass)
	}

	deadline := time.Now().Add(3 * time.Second)
	for len(w.seen()) < 3 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	got := w.seen()
	if len(got) != 3 {
		t.Fatalf("released %v, want 3 packets", got)
	}
	if got[0] != 0 || got[1] != 5 || got[2] != 200 {
		t.Fatalf("emitted %v, want 0,5,200 in order", got)
	}
}

// 🚨 THE 56-SECOND STALL. A generation queued behind an older one buffers
// everything it receives, so counters BELOW the first one it happened to see
// arrive afterwards. If it fixes its start from that first packet, those land
// permanently below the watermark: drainLocked cannot reach below `next`, and
// abandonGapLocked used to move the watermark only when the lowest held counter
// was ABOVE it — so the safety valve found them expired forever.
//
// On the device that was ~1400 packets stuck, the valve firing ~3700 times a
// second, and a single iperf run flat at zero from its fourth second to its
// last. A queued generation must therefore pick its start at PROMOTION, from
// the lowest counter it actually holds.
func TestQueuedGenerationDoesNotStrandLowCounters(t *testing.T) {
	const hold = 40 * time.Millisecond
	r, w := newReseq(t, hold)

	_ = r.write(wgPkt(0xAAAA, 0)) // old keypair, emitted at once
	// New keypair, and the connections deliver it out of order: a HIGH counter
	// first, then lower ones. This is the ordinary shape of the fan-out.
	_ = r.write(wgPkt(0xBBBB, 40))
	_ = r.write(wgPkt(0xBBBB, 5))
	_ = r.write(wgPkt(0xBBBB, 6))
	_ = r.write(wgPkt(0xBBBB, 7))

	deadline := time.Now().Add(3 * time.Second)
	for len(w.seen()) < 5 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	got := w.seen()
	if len(got) != 5 {
		t.Fatalf("released %v — %d of 5; low counters were stranded below the watermark", got, len(got))
	}
	if got[0] != 0 || got[1] != 5 || got[2] != 6 || got[3] != 7 || got[4] != 40 {
		t.Fatalf("emitted %v, want old(0) then new(5,6,7,40)", got)
	}

	// And nothing may be left unreachable, which is what made the valve spin.
	r.mu.Lock()
	stuck, valves := 0, r.valves
	for _, g := range r.gens {
		for c := range g.held {
			if c < g.next {
				stuck++
			}
		}
	}
	r.mu.Unlock()
	if stuck != 0 {
		t.Fatalf("%d packets left below the watermark — unreachable forever", stuck)
	}
	if valves > 10 {
		t.Fatalf("valve fired %d times — spinning on an unreachable entry", valves)
	}
}

// Handshakes carry no counter and must never be delayed — holding one could
// break the session, and there are far too few to matter.
func TestHandshakesAreNeverHeld(t *testing.T) {
	r, w := newReseq(t, time.Hour)
	_ = r.write(wgPkt(1, 0))
	_ = r.write(wgPkt(1, 9)) // creates a gap, so anything held would stay held
	hs := wgPkt(1, 0)
	hs[0] = 1 // handshake initiation
	_ = r.write(hs)
	w.mu.Lock()
	raw := w.raw
	w.mu.Unlock()
	if raw != 1 {
		t.Fatalf("handshake writes = %d, want 1 — it was buffered behind a gap", raw)
	}
}

func TestCloseFlushesHeldPackets(t *testing.T) {
	r, w := newReseq(t, time.Hour)
	_ = r.write(wgPkt(1, 0))
	for i := uint64(2); i < 10; i++ {
		_ = r.write(wgPkt(1, i))
	}
	if len(w.seen()) != 1 {
		t.Fatalf("released %d before close, want 1", len(w.seen()))
	}
	r.close()
	got := w.seen()
	if len(got) != 9 {
		t.Fatalf("wrote %d after close, want 9 — teardown swallowed packets that had already crossed the network", len(got))
	}
	if inversions(got) != 0 {
		t.Fatal("close released out of order")
	}
}

// The write path is hit by every connection's goroutine at once.
func TestConcurrentWritersKeepOrderAndLoseNothing(t *testing.T) {
	r, w := newReseq(t, 500*time.Millisecond)
	const n = 3000
	// A shared cursor mimics one WireGuard sender feeding N carriers.
	var mu sync.Mutex
	next := uint64(0)
	take := func() (uint64, bool) {
		mu.Lock()
		defer mu.Unlock()
		if next >= n {
			return 0, false
		}
		c := next
		next++
		return c, true
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				c, ok := take()
				if !ok {
					return
				}
				time.Sleep(time.Duration(worker%5) * 20 * time.Microsecond)
				_ = r.write(wgPkt(1, c))
			}
		}(i)
	}
	wg.Wait()
	r.close()
	got := w.seen()
	if len(got) != n {
		t.Fatalf("wrote %d of %d — data lost under concurrency", len(got), n)
	}
	// Not asserting zero inversions: the workers race, so the ORDER OF ARRIVAL
	// is genuinely non-deterministic and some packets legitimately arrive after
	// their slot expired. The invariant that must hold is conservation.
}

// 🚨 A percentile must be normalised by the thing it is a percentile OF.
//
// `buffered` counts packets going IN to the hold buffer; the hold histogram is
// filled when they come OUT. At every interval boundary the difference is
// whatever is still held — so dividing by `buffered` walked the cumulative off
// the end of the histogram and printed the OVERFLOW bucket. A device run showed
// "p99 512 ms" next to "max 31ms", and only that impossibility caught it.
//
// The case below is the extreme of it: everything is still held, so the
// histogram is empty and the honest answer is "no data", not 512.
func TestHoldPercentilesAreNormalisedByReleasedPacketsNotBuffered(t *testing.T) {
	r, _ := newReseq(t, time.Hour) // nothing will be released by a timer
	_ = r.write(wgPkt(1, 0))       // straight through, never buffered
	for i := uint64(2); i <= 40; i++ {
		_ = r.write(wgPkt(1, i)) // all held behind the gap at 1
	}
	if r.buffered != 39 {
		t.Fatalf("buffered = %d, want 39", r.buffered)
	}
	line := r.summaryAndReset()
	for _, bad := range []string{"512", strconv.Itoa(reseqHoldBuckets)} {
		if strings.Contains(line, bad+"/") || strings.Contains(line, "/"+bad+" ms") {
			t.Fatalf("percentile fell into the overflow bucket: %q", line)
		}
	}
	if !strings.Contains(line, "-1/-1/-1 ms") {
		t.Fatalf("with nothing released the percentiles must report no data, got %q", line)
	}
	if !strings.Contains(line, "over 0 released") {
		t.Fatalf("the line must say how many packets the hold stats cover: %q", line)
	}
	r.close()
}

// And the ordinary case: released packets are summarised over themselves.
func TestHoldPercentilesCoverTheReleasedPackets(t *testing.T) {
	r, _ := newReseq(t, time.Hour)
	_ = r.write(wgPkt(1, 0))
	for i := uint64(1); i <= 20; i++ {
		_ = r.write(wgPkt(1, i)) // arrives in order after the first — nothing held
	}
	// Now hold three behind a gap, then fill it so they drain.
	for _, c := range []uint64{23, 24, 25} {
		_ = r.write(wgPkt(1, c))
	}
	_ = r.write(wgPkt(1, 21))
	_ = r.write(wgPkt(1, 22))
	line := r.summaryAndReset()
	if !strings.Contains(line, "over 3 released") {
		t.Fatalf("want 3 released packets in the hold stats: %q", line)
	}
	r.close()
}

// logSink captures the standard logger. It needs the mutex: the resequencer's
// timer goroutine writes the promotion line, and the test reads it.
type logSink struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *logSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// 🎯 The rekey lifecycle must be LOGGED, not merely counted.
//
// `keypairs R/G` in conn-stats places a rotation somewhere inside a 2 s window,
// which on 2026-08-10 was not enough to say whether a rotation preceded a
// one-second stall in the client's trace or followed it. These three lines carry
// the instants. The promotion line also re-guards the start-at-promotion fix
// from the outside: it prints the start counter, which must be the LOWEST held
// (3 here), not the first one seen (5).
func TestGenerationLifecycleIsLogged(t *testing.T) {
	// ⚠️ 200 ms, not 40: the four writes below must all land inside ONE hold or
	// the rekey plays out differently, and 40 ms is not a safe margin for four
	// unsynchronised writes on a loaded -race runner.
	const hold = 200 * time.Millisecond
	sink := &logSink{}
	prev := log.Writer()
	log.SetOutput(sink)
	defer log.SetOutput(prev)

	r, w := newReseq(t, hold)
	_ = r.write(wgPkt(0xAAAA, 0)) // old keypair, out at once
	_ = r.write(wgPkt(0xAAAA, 2)) // old keypair, held behind the gap at 1
	_ = r.write(wgPkt(0xBBBB, 5)) // new keypair — queued, and the HIGH counter first
	_ = r.write(wgPkt(0xBBBB, 3))

	deadline := time.Now().Add(5 * time.Second)
	for len(w.seen()) < 4 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if n := len(w.seen()); n != 4 {
		t.Fatalf("released %d of 4 — the rekey did not complete, so the log cannot be read", n)
	}
	// Flush teardown into the SINK. t.Cleanup runs AFTER the deferred restore
	// above, so without this the CLOSED line for the surviving generation goes
	// to the terminal and the test silently reads a shorter log than it thinks.
	r.close()

	got := sink.text()
	for _, want := range []string{
		"keypair 0x0000aaaa opened at ctr 0",
		"keypair 0x0000bbbb OPENED at ctr 5",
		"QUEUED behind 1 generation(s), oldest 0x0000aaaa",
		"keypair 0x0000aaaa CLOSED",
		"keypair 0x0000bbbb PROMOTED",
		"start ctr 3", // the LOWEST held, not the first seen (5) — the a5392ee fix
		"2 pkts seen", // `seen` counts this keypair's packets
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log is missing %q; got:\n%s", want, got)
		}
	}

	// The CLOSED line's numbers are load-bearing, so assert them rather than the
	// bare word: `%d pkts` pins `seen`, and a lifetime of at least one hold pins
	// `firstSeen` to CREATION — stamped at close instead it would print ~0s.
	m := regexp.MustCompile(`keypair 0x0000aaaa CLOSED after (\S+), (\d+) pkts`).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("CLOSED line does not carry a lifetime and a packet count:\n%s", got)
	}
	// ⚠️ BOTH ends of the range. A lower bound alone passes when firstSeen is the
	// ZERO time — time.Since(zero) is ~2000 years, comfortably "at least one
	// hold" — which is exactly the mutant that slipped through the first version
	// of this assertion.
	lifetime, err := time.ParseDuration(m[1])
	if err != nil || lifetime < hold || lifetime > 30*time.Second {
		t.Fatalf("CLOSED after %q (err %v) — must be at least %s (the quiet before a close) "+
			"and less than this test's own runtime, so firstSeen is stamped at CREATION "+
			"and is a real timestamp", m[1], err, hold)
	}
	if m[2] != "2" {
		t.Fatalf("CLOSED reports %s pkts, want 2 — `seen` is not counting", m[2])
	}

	// Exactly one promotion. Two would mean an ordinary close was reported as a
	// promotion; none would mean the queued side never reached the front.
	if n := strings.Count(got, "PROMOTED"); n != 1 {
		t.Fatalf("PROMOTED appears %d times, want 1:\n%s", n, got)
	}
	// Order matters as much as presence: a promotion logged before the close it
	// waited for would mean the two sides of the rekey were not serialised.
	iOpen := strings.Index(got, "keypair 0x0000bbbb OPENED")
	iClose := strings.Index(got, "keypair 0x0000aaaa CLOSED")
	iProm := strings.Index(got, "keypair 0x0000bbbb PROMOTED")
	if !(iOpen < iClose && iClose < iProm) {
		t.Fatalf("lines out of order (open %d, close %d, promote %d):\n%s", iOpen, iClose, iProm, got)
	}
}

// 🚨 THE LIFECYCLE LOG MUST NOT BE DRIVEN BY THE PACKET RATE.
//
// Four lines per rekey is ~4 every 120 s. But genLocked's force-close loop fires
// once per PACKET whose receiver index is not one of the three tracked, and each
// iteration emits four lines — 4.00 per packet, measured, with r.mu held and
// -logfile turning each into a synchronous write(2) inside the critical section
// that every uplink writer contends on. `idx` comes straight out of the packet
// with no WireGuard validation, so a remote peer sets that rate.
func TestLifecycleLogIsRateLimited(t *testing.T) {
	sink := &logSink{}
	prev := log.Writer()
	log.SetOutput(sink)
	defer log.SetOutput(prev)

	r, _ := newReseq(t, 100*time.Millisecond)
	const n = 2000
	for i := 0; i < n; i++ {
		_ = r.write(wgPkt(uint32(0x10000+i), uint64(i))) // a fresh keypair every packet
	}
	got := sink.text()
	// This test is only meaningful if it actually reaches the cascade.
	if !strings.Contains(got, "force-closing the oldest") {
		t.Fatalf("the force-close path was never taken, so nothing was tested:\n%s", got)
	}
	lines := strings.Count(got, "reseq[test]")
	// ⚠️ An ABSOLUTE ceiling, deliberately not `k × reseqLogPerSec`: deriving the
	// threshold from the constant under test means raising the constant also
	// relaxes the assertion, and the sabotage run then stays green. If someone
	// legitimately raises the budget past this, they should have to look at this
	// line — that is the point of it.
	const ceiling = 40 // one budget per second, a loop that runs in milliseconds
	if lines > ceiling {
		t.Fatalf("%d lines for %d packets (ceiling %d) — the budget did not bind", lines, n, ceiling)
	}
	if lines == 0 {
		t.Fatal("no lines at all — the budget swallowed the signal instead of bounding it")
	}
	// Suppression must be VISIBLE. A cap that hides a storm is worse than no cap.
	s := r.summaryAndReset()
	dm := regexp.MustCompile(`log-drop (\d+)`).FindStringSubmatch(s)
	if dm == nil {
		t.Fatalf("the dump does not report suppressed lines: %s", s)
	}
	if dm[1] == "0" {
		t.Fatalf("log-drop is 0 after %d packets of cascade — suppression is not counted: %s", n, s)
	}
	if again := r.summaryAndReset(); strings.Contains(again, "log-drop") &&
		!strings.Contains(again, "log-drop 0") {
		t.Fatalf("log-drop was not reset by the dump: %s", again)
	}
}

func TestSummaryLineAndReset(t *testing.T) {
	r, _ := newReseq(t, time.Hour)
	_ = r.write(wgPkt(1, 0))
	_ = r.write(wgPkt(1, 3))
	s := r.summaryAndReset()
	if s == "" {
		t.Fatal("no summary line")
	}
	if got := r.summaryAndReset(); got != "" {
		t.Fatalf("counters were not reset: %q", got)
	}
	r.close()
}
