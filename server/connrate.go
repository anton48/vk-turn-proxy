package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// A PER-CONNECTION INSTANTANEOUS UPLINK RATE SAMPLER, at ~100 ms.
//
// 🎯 THE QUESTION IT EXISTS FOR. The 2026-08-15 dose-response runs established
// that a PACED stream at ~97% of the per-allocation knee loses 0.02% while real
// TCP at a MEDIAN of 71% loses 0.77-1.16% — so what is lost is BURST STRUCTURE,
// not the average level. Every instrument we had reads the load over 2 SECONDS,
// and a 2 s average cannot resolve a sub-second overshoot: it is the reason the
// token-bucket form of VK's meter survives while the rate-clip form is refuted.
// This sampler is the missing resolution.
//
// 🚨 WHAT IT MEASURES, STATED PRECISELY, BECAUSE IT IS NOT WHAT THE PHONE SENT.
// The counters tick when server1 READS a packet off the relay connection, i.e.
// AFTER the meter. So this is the rate that SURVIVED, not the rate offered:
//
//   - A hard rate limiter could never let a sample exceed 100%, so a run with
//     no over-knee samples does NOT prove the phone never overshot.
//   - A TOKEN BUCKET does let bursts through while it has tokens, which is
//     exactly why over-knee samples are visible at all (the 264 analysis read
//     110-134% of the knee at the receiver). ⇒ **the informative signature is
//     over-knee samples FOLLOWED by a loss episode** — the bucket emptying.
//
// That is why the worst windows are logged with their TIMESTAMPS: the loss
// counter in reorder.go is keyed per receiver index and this is keyed per
// connection, so the two can only be joined on time, offline, and ⚠️ `lost` is
// deferred by up to one 8128-counter window (~2 s) which the alignment must
// allow for.
//
// ⚠️ RESOLUTION IS BOUNDED BY PACKET QUANTISATION. At 100 ms and ~2 Mbit/s a
// connection carries ~19 packets, so one packet is ~5% — which is why the
// histogram is 5% wide and no finer. At a third of that load the quantum is
// ~15% and the percentiles below 40% of the knee mean very little. Read the
// SHAPE near the knee, not the low tail.
//
// ⚠️ UPLINK ONLY. The downlink is paced by us and is not the open question.

const (
	// connRateWireOverhead is the framing the policer counts and the byte
	// counter does not — measured at ~30 B/packet → reference_throughput_limits.
	connRateWireOverhead = 30

	// connRateKneeBytes is the per-allocation knee, in WIRE bytes per second.
	// 🚨 The knee is BRACKETED BY MEASUREMENT at 247-260 KiB/s, not known to a
	// single value; this is the midpoint, and every line prints both it and the
	// absolute KiB/s so a reader can re-derive against either end. Do not quote
	// a percentage from here to three digits — it is worth ±3%.
	connRateKneeBytes = 253 * 1024

	// The histogram: 5%-wide buckets up to 200% of the knee, plus one overflow.
	// 🚨 The width is chosen so that a bucket EDGE FALLS ON 100% — the whole
	// question is "did it cross the knee", and a bucketing that straddles the
	// deciding value instead of landing on it is a mistake this project has
	// already paid for twice.
	connRateBucketPct = 5.0
	connRateBuckets   = 40 // 0..200% in 5% steps; index 40 is ">200%"

	// How many individual over-knee windows to name per dump. Bounded on
	// purpose: this runs 10× a second across 30 connections and the log budget
	// is a real constraint here (a force-close path once emitted four lines per
	// PACKET under a mutex).
	connRateWorstKept = 3
)

// connRateInterval is the sampling period. 0 disables the sampler entirely,
// including its goroutine and its per-connection state.
var connRateInterval = 100 * time.Millisecond

// connRateReading is one connection's counters at one instant. The sampler
// takes these as an argument rather than reaching into the registry so that the
// arithmetic can be tested without goroutines or clocks.
type connRateReading struct {
	id    int
	bytes int64
	pkts  int64
}

type connRatePrev struct {
	bytes int64
	pkts  int64
}

type connRateWindow struct {
	at   time.Time
	id   int
	pct  float64
	rate float64 // wire bytes/s
}

type connRateSampler struct {
	mu sync.Mutex

	// 🚨 INDEPENDENT PREVIOUS STATE. The 2 s dump keeps its own prevUp/prevDn in
	// the registry; two samplers differencing the same counters MUST NOT share
	// that state or each one's read resets the other's baseline and both print
	// nonsense. Learned the expensive way elsewhere in this file's neighbourhood.
	prev   map[int]connRatePrev
	prevAt time.Time

	buckets    [connRateBuckets + 1]int64
	samples    int64
	slow       int64 // samples whose interval stretched past 2× nominal
	overByConn map[int]int64
	maxPct     float64
	maxConn    int
	maxRate    float64
	worst      []connRateWindow
}

var connRate = newConnRateSampler()

func newConnRateSampler() *connRateSampler {
	return &connRateSampler{
		prev:       make(map[int]connRatePrev),
		overByConn: make(map[int]int64),
	}
}

// rateReadings snapshots every live connection's uplink counters.
func (r *connRegistry) rateReadings() []connRateReading {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]connRateReading, 0, len(r.conns))
	for id, c := range r.conns {
		out = append(out, connRateReading{id: id, bytes: c.up.Load(), pkts: c.upPkts.Load()})
	}
	return out
}

// runConnRateLoop samples every connRateInterval for the life of the process.
func runConnRateLoop(done <-chan struct{}) {
	if connRateInterval <= 0 {
		log.Printf("conn-rate sampler: OFF (-conn-rate-sample=0). " +
			"The 2 s dump cannot resolve a sub-second overshoot, so a null on " +
			"burst clipping from this run means nothing.")
		return
	}
	log.Printf("conn-rate sampler: every %s, knee %d B/s of WIRE bytes "+
		"(payload + %d B/packet); reports the DISTRIBUTION per conn-stats dump, "+
		"never per sample.", connRateInterval, connRateKneeBytes, connRateWireOverhead)
	t := time.NewTicker(connRateInterval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			connRate.sample(now, registry.rateReadings())
		}
	}
}

// sample differences each connection's counters against this sampler's own
// previous reading and files the resulting instantaneous rate.
func (s *connRateSampler) sample(now time.Time, rd []connRateReading) {
	s.mu.Lock()
	defer s.mu.Unlock()

	first := s.prevAt.IsZero()
	dt := now.Sub(s.prevAt).Seconds()

	seen := make(map[int]bool, len(rd))
	for _, r := range rd {
		seen[r.id] = true
		p, had := s.prev[r.id]
		s.prev[r.id] = connRatePrev{bytes: r.bytes, pkts: r.pkts}
		if first || !had || dt <= 0 {
			// No baseline for this connection yet: a delta cannot be formed and
			// inventing one from zero would report a whole connection's history
			// as a single 100 ms burst.
			continue
		}
		db, dp := r.bytes-p.bytes, r.pkts-p.pkts
		if db < 0 || dp < 0 {
			// A counter that went backwards means the id was reused; drop the
			// sample rather than emitting a negative rate.
			continue
		}
		wire := float64(db) + float64(dp)*connRateWireOverhead
		s.record(now, r.id, wire/dt)
	}

	for id := range s.prev {
		if !seen[id] {
			delete(s.prev, id)
		}
	}
	if !first && dt > 2*connRateInterval.Seconds() {
		// A stretched interval averages the peak away, i.e. it biases toward
		// "no overshoot" — the direction that would fake a null. Counted so a
		// reader can see it happened.
		s.slow++
	}
	s.prevAt = now
}

func (s *connRateSampler) record(at time.Time, id int, rate float64) {
	pct := 100 * rate / connRateKneeBytes
	s.samples++

	i := int(pct / connRateBucketPct)
	if i < 0 {
		i = 0
	}
	if i > connRateBuckets {
		i = connRateBuckets
	}
	s.buckets[i]++

	// 🚨 `>=`, not `>`: the knee is where clipping BEGINS, so a sample sitting
	// exactly on it has reached it.
	if pct >= 100 {
		s.overByConn[id]++
	}
	if pct > s.maxPct {
		s.maxPct, s.maxConn, s.maxRate = pct, id, rate
	}

	if pct >= 100 {
		s.worst = append(s.worst, connRateWindow{at: at, id: id, pct: pct, rate: rate})
		// Keep only the top few, by percentage.
		if len(s.worst) > connRateWorstKept {
			worstIdx := 0
			for j := 1; j < len(s.worst); j++ {
				if s.worst[j].pct < s.worst[worstIdx].pct {
					worstIdx = j
				}
			}
			s.worst = append(s.worst[:worstIdx], s.worst[worstIdx+1:]...)
		}
	}
}

// pctile reads a percentile off the histogram as the LOWER edge of the bucket
// it falls in, so p50 <= p90 <= p99 <= max holds mechanically and no reader can
// be handed a percentile above the exact maximum.
func (s *connRateSampler) pctile(q float64) float64 {
	if s.samples == 0 {
		return 0
	}
	target := int64(float64(s.samples) * q)
	var c int64
	for i := 0; i <= connRateBuckets; i++ {
		c += s.buckets[i]
		if c > target {
			return float64(i) * connRateBucketPct
		}
	}
	return connRateBuckets * connRateBucketPct
}

// dumpAndReset prints the distribution and clears it. 🚨 It does NOT clear the
// per-connection baselines: doing so would throw away one sample after every
// dump, and at a 2 s dump over a 100 ms sampler that is 5% of the data — a
// silent, load-dependent hole.
func (s *connRateSampler) dumpAndReset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.samples == 0 {
		// Silence rather than a row of zeros: an instrument that prints zeros
		// when it has nothing cannot be told from one that measured zero.
		return
	}

	over := int64(0)
	worstConn, worstConnN := 0, int64(0)
	for id, n := range s.overByConn {
		over += n
		// 🚨 THE TIE MUST BREAK THE SAME WAY EVERY TIME. Go randomises map
		// iteration, so without the id comparison two connections with equal
		// counts would put a DIFFERENT name in the log on every dump — and the
		// first question anyone asks of this line is "is it the same connection
		// each time?". An instrument that answers that question at random is
		// worse than one that does not answer it. (Found 2026-08-15 by a test of
		// mine that was itself passing on luck.)
		if n > worstConnN || (n == worstConnN && worstConnN > 0 && id < worstConn) {
			worstConn, worstConnN = id, n
		}
	}
	slowNote := ""
	if s.slow > 0 {
		slowNote = fmt.Sprintf(" ⚠️ %d stretched intervals (peaks averaged away)", s.slow)
	}
	log.Printf("  conn-rate(%s): %d samples over %d conns | p50 %.0f%% p90 %.0f%% p99 %.0f%% "+
		"max %.0f%% = %.0f KiB/s on conn %d | knee %d KiB/s wire%s",
		connRateInterval, s.samples, len(s.prev),
		s.pctile(0.50), s.pctile(0.90), s.pctile(0.99),
		s.maxPct, s.maxRate/1024, s.maxConn, connRateKneeBytes/1024, slowNote)

	// 🚨 Read the second line before believing the first. "One connection hit
	// 187%" is a MAX over hundreds of samples and says nothing on its own; the
	// question rule 5 makes us ask is whether it is the SAME connection each
	// time. `on N of M conns` answers it.
	if over > 0 {
		windows := make([]string, 0, len(s.worst))
		for _, w := range s.worst {
			windows = append(windows, fmt.Sprintf("%s c%d %.0f%%",
				w.at.Format("15:04:05.000"), w.id, w.pct))
		}
		log.Printf("  conn-rate over-knee: %d samples (%.2f%%) on %d of %d conns, "+
			"worst conn %d with %d | windows %v — join these to `lost` on TIME, "+
			"allowing for its one-window deferral",
			over, 100*float64(over)/float64(s.samples),
			len(s.overByConn), len(s.prev), worstConn, worstConnN, windows)
	}

	for i := range s.buckets {
		s.buckets[i] = 0
	}
	s.samples, s.slow = 0, 0
	s.overByConn = make(map[int]int64)
	s.maxPct, s.maxConn, s.maxRate = 0, 0, 0
	s.worst = s.worst[:0]
}
