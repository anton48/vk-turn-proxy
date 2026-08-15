package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/server/srtpwrap"
)

// Each of these was SEEN to fail under a sabotage that still COMPILES; the
// sabotage is named above the test.

func captureWG(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()
	fn()
	return buf.String()
}

func resetWGWrite() {
	wgWriteCount.Store(0)
	wgWriteMaxNs.Store(0)
	for i := range wgWriteBuckets {
		wgWriteBuckets[i].Store(0)
	}
}

// Percentiles are lower bucket edges, so the ordering holds by construction and
// no reader is handed a percentile above the exact maximum.
//
// SABOTAGE SEEN TO FAIL: return `wgWriteEdges[i]` instead of `[i-1]` from
// wgWritePctile. Compiles; p99 then exceeds max.
func TestWGWritePercentilesAreMonotoneAndUnderMax(t *testing.T) {
	resetWGWrite()
	for _, d := range []time.Duration{
		10 * time.Microsecond, 20 * time.Microsecond, 30 * time.Microsecond,
		100 * time.Microsecond, 300 * time.Microsecond, 2 * time.Millisecond,
	} {
		observeWGWrite(d)
	}
	counts := make([]int64, len(wgWriteBuckets))
	for i := range wgWriteBuckets {
		counts[i] = wgWriteBuckets[i].Load()
	}
	total := wgWriteCount.Load()
	p50 := wgWritePctile(counts, total, 0.50)
	p90 := wgWritePctile(counts, total, 0.90)
	p99 := wgWritePctile(counts, total, 0.99)
	maxD := time.Duration(wgWriteMaxNs.Load())
	if !(p50 <= p90 && p90 <= p99 && p99 <= maxD) {
		t.Fatalf("p50=%v p90=%v p99=%v max=%v", p50, p90, p99, maxD)
	}
	if maxD != 2*time.Millisecond {
		t.Fatalf("max must be exact, got %v", maxD)
	}
}

// The dump must read AND reset, or a quiet interval inherits the previous
// interval's numbers and every reading after a burst is wrong.
//
// SABOTAGE SEEN TO FAIL: change the `Swap(0)` calls in dumpWGWriteAndReset to
// `Load()`. Compiles; the second dump then still reports six writes.
func TestWGWriteDumpResets(t *testing.T) {
	resetWGWrite()
	for i := 0; i < 6; i++ {
		observeWGWrite(10 * time.Microsecond)
	}
	if out := captureWG(t, dumpWGWriteAndReset); !strings.Contains(out, "6 writes") {
		t.Fatalf("expected the first dump to report 6 writes:\n%s", out)
	}
	if out := captureWG(t, dumpWGWriteAndReset); out != "" {
		t.Fatalf("expected silence after the reset, got:\n%s", out)
	}
}

// 🚨 An instrument that prints zeros when it has nothing cannot be told from one
// that measured zero. With no writes and no queue activity the line is absent.
func TestWGWriteSilentWhenIdle(t *testing.T) {
	resetWGWrite()
	if out := captureWG(t, dumpWGWriteAndReset); out != "" {
		t.Fatalf("expected silence, got:\n%s", out)
	}
}

// 🚨 A drop in the demux lands UPSTREAM of the loss counter, so it must be
// impossible to miss: the line has to SHOUT rather than print a small number
// among others.
//
// SABOTAGE SEEN TO FAIL: pass "" where `note` goes and add `_ = note` so it
// still compiles (deleting it outright does not — unused variable, which would
// validate the compiler rather than the test). This test then finds no warning.
func TestWGWriteShoutsWhenTheDemuxDropped(t *testing.T) {
	resetWGWrite()
	observeWGWrite(time.Millisecond)
	srtpwrap.NoteRTPDrop("test-session")
	out := captureWG(t, dumpWGWriteAndReset)
	if !strings.Contains(out, "DROPPED") || !strings.Contains(out, "UPSTREAM") {
		t.Fatalf("a demux drop must be shouted, and must say where it lands:\n%s", out)
	}
}

// The queue reading must be the PEAK over the interval, not the last sample —
// a queue that filled and drained between two dumps is exactly the event this
// instrument exists to catch.
//
// SABOTAGE SEEN TO FAIL: make noteRTPEnqueued store unconditionally
// (`rtpQueuePeak.Store(int64(depth))`) instead of keeping the maximum.
// Compiles; this test then reads 1 instead of 40.
func TestDemuxQueuePeakIsAMaximum(t *testing.T) {
	resetWGWrite()
	for _, d := range []int{3, 40, 1} {
		srtpwrap.NoteRTPEnqueued(d)
	}
	out := captureWG(t, dumpWGWriteAndReset)
	if !strings.Contains(out, "peak 40/") {
		t.Fatalf("expected the peak depth, not the last one:\n%s", out)
	}
}
