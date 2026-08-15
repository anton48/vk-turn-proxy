package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// Tests for the 100 ms per-connection rate sampler. Every one of them was SEEN
// to fail under a sabotage that still COMPILES — the sabotage is named in the
// comment above each, because a test guarding a silent property is worth
// exactly what its demonstrated failure is worth.

const testTick = 100 * time.Millisecond

var testT0 = time.Date(2026, 8, 15, 13, 0, 0, 0, time.UTC)

// feed runs one sampling pass at t0+step*tick with the given readings.
func feed(s *connRateSampler, step int, rd ...connRateReading) {
	s.sample(testT0.Add(time.Duration(step)*testTick), rd)
}

func capture(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(old); log.SetFlags(flags) }()
	fn()
	return buf.String()
}

// 🚨 THE ONE THAT MATTERS: the policer counts WIRE bytes, so the rate must add
// ~30 B per packet back to the payload the counter holds. Reading bytes alone
// understates every "% of the knee" by 2-3% — small, but it is the difference
// between "94%" and "97%" and the whole question is where the knee is crossed.
//
// SABOTAGE SEEN TO FAIL: drop `+ float64(dp)*connRateWireOverhead` from
// sample(). Compiles; this test then reads 96.2% against the expected 98.4%.
func TestRateCountsWireBytesNotPayload(t *testing.T) {
	s := newConnRateSampler()
	const pkts, size = 19, 1312
	feed(s, 0, connRateReading{id: 1})
	feed(s, 1, connRateReading{id: 1, bytes: pkts * size, pkts: pkts})

	wire := float64(pkts*size + pkts*connRateWireOverhead)
	want := 100 * (wire / testTick.Seconds()) / connRateKneeBytes
	if diff := s.maxPct - want; diff > 0.05 || diff < -0.05 {
		t.Fatalf("wire-corrected rate: got %.2f%%, want %.2f%%", s.maxPct, want)
	}
	payloadOnly := 100 * (float64(pkts*size) / testTick.Seconds()) / connRateKneeBytes
	if s.maxPct <= payloadOnly {
		t.Fatalf("the wire correction did not apply: %.2f%% is not above the "+
			"payload-only %.2f%%", s.maxPct, payloadOnly)
	}
}

// A sample sitting EXACTLY on the knee has reached it. The knee is where
// clipping begins, and a bucketing that puts the deciding value on the safe
// side is how a run at the knee gets filed as a run below it.
//
// SABOTAGE SEEN TO FAIL: `if pct > 100` instead of `>=` in record(). Compiles;
// the over-knee count then reads 0.
func TestKneeIsReachedNotExceeded(t *testing.T) {
	s := newConnRateSampler()
	// One second, 100 packets, payload chosen so payload + framing == the knee.
	const pkts = 100
	payload := int64(connRateKneeBytes - pkts*connRateWireOverhead)
	s.sample(testT0, []connRateReading{{id: 1}})
	s.sample(testT0.Add(time.Second), []connRateReading{{id: 1, bytes: payload, pkts: pkts}})

	if got := s.overByConn[1]; got != 1 {
		t.Fatalf("a sample exactly at the knee must count as reaching it: got %d", got)
	}
	if s.maxPct < 99.9 || s.maxPct > 100.1 {
		t.Fatalf("expected 100%% of the knee, got %.3f%%", s.maxPct)
	}
}

// 🚨 Rule 5, in code: an extreme is not a property until you know whether it is
// the SAME connection each time. The dump must report how many DISTINCT
// connections crossed the knee, not how many samples did.
//
// SABOTAGE SEEN TO FAIL: report `over` (the sample total) where the line prints
// `len(s.overByConn)`. Compiles; the line then reads "on 3 of 2 conns", which
// is also its own absurdity.
func TestOverKneeCountsConnsNotSamples(t *testing.T) {
	s := newConnRateSampler()
	hot := int64(connRateKneeBytes * 2) // per second, comfortably over
	feed(s, 0, connRateReading{id: 1}, connRateReading{id: 2})
	// conn 1 crosses twice, conn 2 once.
	feed(s, 1,
		connRateReading{id: 1, bytes: hot / 10, pkts: 1},
		connRateReading{id: 2, bytes: hot / 10, pkts: 1})
	// 🚨 conn 2 goes QUIET in the second window (+10 bytes, not another hot
	// tick). The first version of this test gave both connections the same
	// second tick, so both crossed twice — a TIE, whose winner came out of Go's
	// randomised map order. It passed about two runs in three, and the flake was
	// the test telling the truth about an unspecified tie-break.
	feed(s, 2,
		connRateReading{id: 1, bytes: 2 * hot / 10, pkts: 2},
		connRateReading{id: 2, bytes: hot/10 + 10, pkts: 1})

	out := capture(t, s.dumpAndReset)
	if !strings.Contains(out, "on 2 of 2 conns") {
		t.Fatalf("expected the DISTINCT connection count in:\n%s", out)
	}
	if !strings.Contains(out, "worst conn 1 with 2") {
		t.Fatalf("expected conn 1 named as the worst with 2 samples in:\n%s", out)
	}
}

// 🚨 AND THE TIE ITSELF MUST BE DETERMINISTIC. Two connections with the same
// count is the ordinary case at high load, and a line that names a different one
// on every dump invites exactly the wrong reading — "it rotates, so nothing is
// structurally hot" — from an artefact of map iteration.
//
// The loop is the test: one dump can pass on luck, fifty cannot.
//
// SABOTAGE SEEN TO FAIL: drop the `|| (n == worstConnN && ...)` clause from
// dumpAndReset, i.e. restore the plain `n > worstConnN`. Compiles; this test
// then fails within a few iterations.
func TestWorstConnIsDeterministicOnATie(t *testing.T) {
	hot := int64(connRateKneeBytes * 2)
	for i := 0; i < 50; i++ {
		s := newConnRateSampler()
		feed(s, 0, connRateReading{id: 7}, connRateReading{id: 3}, connRateReading{id: 5})
		feed(s, 1,
			connRateReading{id: 7, bytes: hot / 10, pkts: 1},
			connRateReading{id: 3, bytes: hot / 10, pkts: 1},
			connRateReading{id: 5, bytes: hot / 10, pkts: 1})
		out := capture(t, s.dumpAndReset)
		if !strings.Contains(out, "worst conn 3 with 1") {
			t.Fatalf("iteration %d: a tie must resolve to the lowest id:\n%s", i, out)
		}
	}
}

// The dump clears the distribution but must NOT clear the per-connection
// baselines: at a 2 s dump over a 100 ms sampler, throwing one sample away each
// time is a silent 5% hole, and it grows as the dump interval shrinks.
//
// SABOTAGE SEEN TO FAIL: add `s.prev = make(map[int]connRatePrev)` to
// dumpAndReset(). Compiles; the sample after the dump then records nothing.
func TestDumpKeepsBaselines(t *testing.T) {
	s := newConnRateSampler()
	feed(s, 0, connRateReading{id: 1})
	feed(s, 1, connRateReading{id: 1, bytes: 10000, pkts: 8})
	capture(t, s.dumpAndReset)

	feed(s, 2, connRateReading{id: 1, bytes: 20000, pkts: 16})
	if s.samples != 1 {
		t.Fatalf("the sample after a dump must still have a baseline: got %d samples", s.samples)
	}
}

// A connection's FIRST reading has no baseline, so no rate can be formed from
// it. Treating the missing baseline as zero would report the connection's whole
// history as one 100 ms burst — an invented overshoot, in the exact direction
// that would make the meter look guilty.
//
// SABOTAGE SEEN TO FAIL: neutralise the guard while keeping `had` referenced so
// it still compiles — `if first || (!had && false) || dt <= 0`. This test then
// reports a connection joining mid-run at 3 723 746% of the knee.
// ⚠️ Simply deleting `!had` does NOT compile (unused variable), and a build
// failure validates the compiler, not the test.
func TestFirstReadingInventsNoBurst(t *testing.T) {
	s := newConnRateSampler()
	feed(s, 0, connRateReading{id: 1, bytes: 500 << 20, pkts: 400000})
	if s.samples != 0 {
		t.Fatalf("the first reading must produce no sample: got %d at %.0f%%",
			s.samples, s.maxPct)
	}
	// And a connection appearing LATER, mid-run, gets the same treatment.
	feed(s, 1, connRateReading{id: 1, bytes: 500 << 20, pkts: 400000})
	feed(s, 2,
		connRateReading{id: 1, bytes: 500 << 20, pkts: 400000},
		connRateReading{id: 2, bytes: 900 << 20, pkts: 700000})
	if s.maxPct != 0 {
		t.Fatalf("a connection joining mid-run must not report a burst: %.0f%%", s.maxPct)
	}
}

// Percentiles are lower bucket edges, so p50 <= p90 <= p99 <= max must hold by
// construction — no reader should ever be handed a percentile above the exact
// maximum, which is the shape that made an earlier histogram unreadable.
//
// SABOTAGE SEEN TO FAIL: return the UPPER edge (`float64(i+1)*bucket`) from
// pctile(). Compiles; p99 then exceeds max on this distribution.
func TestPercentilesAreMonotoneAndBoundedByMax(t *testing.T) {
	s := newConnRateSampler()
	feed(s, 0, connRateReading{id: 1})
	var bytes int64
	for i := 1; i <= 50; i++ {
		// A rising ramp, so the percentiles are genuinely spread out.
		bytes += int64(i) * 500
		feed(s, i, connRateReading{id: 1, bytes: bytes, pkts: int64(i)})
	}
	p50, p90, p99 := s.pctile(0.50), s.pctile(0.90), s.pctile(0.99)
	if !(p50 <= p90 && p90 <= p99 && p99 <= s.maxPct) {
		t.Fatalf("percentiles must be monotone and under the max: "+
			"p50=%.0f p90=%.0f p99=%.0f max=%.2f", p50, p90, p99, s.maxPct)
	}
}

// A connection that goes away must take its baseline with it. 🚨 My first
// version of this test asserted that a REUSED id cannot difference against a
// stranger's counters — and it passed with the pruning deleted, because the
// `db < 0` guard already covers that, and because ids come from a monotonic
// `nextID++` and are never reused at all. The test was vacuous: it guarded a
// property another guard already provided.
//
// What pruning actually protects is the map: without it, `prev` grows for the
// life of the process, and the dump's "on N of M conns" denominator counts
// connections that closed hours ago — the number a reader uses to decide
// whether an overshoot is one hot connection or the whole pool.
//
// SABOTAGE SEEN TO FAIL: remove the `for id := range s.prev { if !seen[id] ... }`
// pruning. Compiles; `prev` then holds 3 and the line says "of 3 conns".
func TestVanishedConnIsForgotten(t *testing.T) {
	s := newConnRateSampler()
	feed(s, 0,
		connRateReading{id: 1}, connRateReading{id: 2}, connRateReading{id: 3})
	feed(s, 1,
		connRateReading{id: 1, bytes: 40000, pkts: 30},
		connRateReading{id: 2, bytes: 40000, pkts: 30},
		connRateReading{id: 3, bytes: 40000, pkts: 30})
	// Two of them close.
	feed(s, 2, connRateReading{id: 2, bytes: 80000, pkts: 60})

	if len(s.prev) != 1 {
		t.Fatalf("closed connections must be forgotten: prev holds %d, want 1", len(s.prev))
	}
	out := capture(t, s.dumpAndReset)
	if !strings.Contains(out, "over 1 conns") {
		t.Fatalf("the dump must count only live connections:\n%s", out)
	}
}

// An instrument that prints zeros when it has nothing cannot be told from one
// that measured zero. With no samples the dump must be silent.
func TestSilentWhenNothingWasSampled(t *testing.T) {
	s := newConnRateSampler()
	if out := capture(t, s.dumpAndReset); out != "" {
		t.Fatalf("expected silence, got:\n%s", out)
	}
}
