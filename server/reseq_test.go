package main

import (
	"math/rand"
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
