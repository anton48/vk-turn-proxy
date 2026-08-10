package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"
	"time"
)

// M5 — put the client's uplink back in order before WireGuard sees it.
//
// THE PROBLEM, measured twice by independent instruments. The client stripes one
// inner flow across N TURN connections whose latencies differ, so at the point
// where they merge the stream is shuffled: 74.2% of inner TCP segments arrive
// displaced (server2 capture, TCP sequence space) and 72.5-79.1% of WireGuard
// packets do (server1, reorder.go, counter space) — median depth ~N/2. There is
// NO loss: every retransmission observed was spurious.
//
// 🎯 WHAT IT IS WORTH, measured 2026-08-10 with iperf3, ONE stream, nothing
// varying but the hold: off **2.95** → 30 ms **4.93** → 100 ms **9.46** →
// 150 ms **13.0 Mbit/s**. Monotone, 4.4×. The same phone does 73.0 Mbit/s
// single-stream with no VPN, so reordering — not path length — was the cost.
//
// ⚠️ AND WHAT IT IS NOT WORTH YET. On a MULTI-stream workload it makes things
// worse (Ookla at 100 ms: 12.2 against 16-26 without), because that workload
// sits on a SECOND, still-unexplained limit — an aggregate ~22-26 Mbit/s
// reached at ~8 flows — where a per-flow gain cannot appear. Default stays 0.
//
// WireGuard tolerates the shuffle (replay window 8128) but does not repair it:
// it hands packets to the TUN in arrival order, so the inner TCP inherits it.
//
// 🚨 WHY THIS CANNOT LOSE DATA. Three rules, in order of importance:
//
//  1. A packet is never dropped. One that arrives after its slot was released
//     is written through immediately, out of order. That is strictly better
//     than dropping it: the hole is already visible to the inner TCP and a late
//     fill is what SACK wants, whereas a drop would manufacture real loss.
//  2. The wait is bounded per packet by reseqMaxWaitFactor × holdFor, and
//     separately by maxHeld packets.
//  3. Only transport messages are held. Handshakes carry no counter and pass
//     straight through — delaying one could break the session.
//
// ⚠️ THERE IS A STARTUP TRANSIENT per generation, and it is unavoidable. The
// first transport packet of a keypair defines where its sequence starts, so a
// packet with a LOWER counter arriving afterwards has missed its slot. Bounded
// by the reorder depth, once per keypair.
//
// The resequencer lives on the GROUP's hub, because a group is exactly the set
// of connections that merge. A connection with its own private socket has
// nothing to merge with and is left alone.

const (
	// maxHeld bounds memory and the damage a stuck sequence can do, across all
	// live generations together.
	reseqMaxHeld = 2048

	// Hold time is reported as a distribution, not just a mean. The defect that
	// made that necessary hid behind a 3.2 ms mean in one phase while another
	// phase of the same run sat at 191 ms.
	reseqHoldBuckets = 512 // milliseconds, plus one overflow bucket

	// A packet may wait this many holdFor before the safety valve opens and the
	// current gap is abandoned wholesale. Without it, a run of genuinely missing
	// counters would cost holdFor EACH — see waitForHoleLocked.
	reseqMaxWaitFactor = 3

	// At most this many keypairs are tracked at once. Two is the real number
	// (old + new across a rekey); a third means something is wrong and the
	// oldest is force-closed rather than accumulating.
	reseqMaxGens = 3

	// Floor on re-arming, so no reachable state can spin the timer. See armLocked.
	reseqMinRearm = 5 * time.Millisecond
)

// uplinkReseqHold is the hold timer from the command line. Zero disables the
// resequencer entirely, which is the default — this is a treatment, and a run
// without it is the control that says whether it did anything.
var uplinkReseqHold time.Duration

// generation is one keypair's counter sequence.
//
// 🚨 WHY GENERATIONS EXIST. WireGuard rekeys about every two minutes and the
// counter restarts at zero under a NEW receiver index. During the switch the
// client's N connections carry BOTH keypairs for a while, so a single "current
// index" thrashes: every packet of the other keypair resets the sequence. The
// first version did exactly that and produced a 4.855 s hold against a 150 ms
// bound, with output displacement p50 1024 and max 5572 — once per rekey.
//
// Generations also fix an ordering point that a single index cannot express:
// the sender switches keypairs at an instant, so EVERY old-keypair packet
// precedes every new-keypair one in the inner stream. Emitting strictly from
// the oldest open generation preserves that; a bare per-index map would not.
// heldPkt keeps the packet and its arrival time TOGETHER.
//
// 🚨 They used to live in two parallel maps, and a device run then showed the
// safety valve firing ~1875 times a SECOND while nothing was held — which is
// only possible if a timestamp outlived its packet, leaving a deadline that
// could never be cleared and a timer that re-armed at its floor forever. I
// could not reproduce it from the code or under a stress test shaped like the
// device's traffic, so this removes the CLASS instead of hunting the instance:
// with one map there is no second map to fall out of step with.
type heldPkt struct {
	buf []byte
	at  time.Time
}

type generation struct {
	idx       uint32
	next      uint64             // the counter we are waiting for
	held      map[uint64]heldPkt // counters above next, with their arrival time
	holeSince time.Time          // when we started waiting for `next`
	lastSeen  time.Time          // last packet of this keypair
}

func newGeneration(idx uint32, ctr uint64, now time.Time) *generation {
	return &generation{
		idx: idx, next: ctr,
		held:      map[uint64]heldPkt{},
		holeSince: now,
		lastSeen:  now,
	}
}

// resequencer restores counter order for one group of connections.
type resequencer struct {
	mu   sync.Mutex
	w    io.Writer
	name string

	// gens is ordered oldest-first. Only gens[0] emits; later generations hold
	// until it closes, because their packets are later in the inner stream.
	hold  time.Duration // captured at construction; never read from a global
	gens  []*generation
	timer *time.Timer

	// Interval counters, read and reset by the conn-stats dump.
	total      int64 // transport packets seen
	passed     int64 // already in order, written straight through
	buffered   int64 // held at least momentarily
	timeouts   int64 // holes given up on after holdFor
	valves     int64 // gaps abandoned wholesale by the safety valve
	overflows  int64 // gaps abandoned because maxHeld was reached
	rekeys     int64 // generations opened after the first
	lateBypass int64 // arrived after its slot was released — written anyway
	holdNs     int64 // total time packets spent held
	holdMs     [reseqHoldBuckets + 1]int64
	maxHold    time.Duration
	maxHeldObs int
}

// newResequencer captures the hold ONCE, at construction.
//
// ⚠️ It used to read the global on every timer firing, which is a data race
// waiting for anyone who writes that global — the test harness did, and the
// race detector caught it. A timer goroutine should not read state it does not
// own.
func newResequencer(w io.Writer, name string, hold time.Duration) *resequencer {
	return &resequencer{w: w, name: name, hold: hold}
}

// write takes one uplink packet on its way to WireGuard. It returns the error
// of whatever it actually wrote, so the caller's error handling is unchanged.
//
// ⚠️ pkt is the caller's read buffer and is reused on the next read. Anything
// retained here MUST be copied.
func (r *resequencer) write(pkt []byte) error {
	if len(pkt) < wgTransportHdrLen || pkt[0] != wgMsgTypeTransport {
		return r.passthrough(pkt)
	}
	idx := binary.LittleEndian.Uint32(pkt[4:8])
	ctr := binary.LittleEndian.Uint64(pkt[8:16])
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++

	g := r.genLocked(idx, ctr, now)
	g.lastSeen = now

	// Only the oldest generation may emit. A newer one buffers until the older
	// closes, which is what keeps the two sides of a rekey in order.
	if g != r.gens[0] {
		r.holdLocked(g, ctr, pkt, now)
		r.armLocked(now)
		return nil
	}

	switch {
	case ctr < g.next:
		// Its slot is gone. Forward rather than drop — rule 1.
		r.lateBypass++
		return r.writeLocked(pkt)

	case ctr == g.next:
		r.passed++
		if err := r.writeLocked(pkt); err != nil {
			return err
		}
		g.next++
		g.holeSince = now
		r.drainLocked(g)
		r.armLocked(now)
		return nil
	}

	r.holdLocked(g, ctr, pkt, now)
	if r.heldCountLocked() > reseqMaxHeld {
		r.overflows++
		r.abandonGapLocked(g, now)
	}
	r.armLocked(now)
	return nil
}

// genLocked finds or creates the generation for a receiver index.
func (r *resequencer) genLocked(idx uint32, ctr uint64, now time.Time) *generation {
	for _, g := range r.gens {
		if g.idx == idx {
			return g
		}
	}
	if len(r.gens) > 0 {
		r.rekeys++
	}
	g := newGeneration(idx, ctr, now)
	r.gens = append(r.gens, g)
	// More than two live keypairs is not a thing WireGuard does; force-close the
	// oldest rather than let the list grow.
	for len(r.gens) > reseqMaxGens {
		r.closeOldestLocked()
	}
	return g
}

func (r *resequencer) holdLocked(g *generation, ctr uint64, pkt []byte, now time.Time) {
	r.buffered++
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	if old, dup := g.held[ctr]; dup {
		now = old.at // a duplicate keeps the original's clock
	}
	g.held[ctr] = heldPkt{buf: cp, at: now}
	if n := r.heldCountLocked(); n > r.maxHeldObs {
		r.maxHeldObs = n
	}
}

func (r *resequencer) heldCountLocked() int {
	n := 0
	for _, g := range r.gens {
		n += len(g.held)
	}
	return n
}

// drainLocked releases every packet of g that has become contiguous.
func (r *resequencer) drainLocked(g *generation) {
	for {
		h, ok := g.held[g.next]
		if !ok {
			break
		}
		r.recordHold(time.Since(h.at))
		delete(g.held, g.next)
		_ = r.writeLocked(h.buf)
		g.next++
	}
}

func (r *resequencer) recordHold(d time.Duration) {
	r.holdNs += int64(d)
	if d > r.maxHold {
		r.maxHold = d
	}
	ms := int(d / time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	if ms > reseqHoldBuckets {
		ms = reseqHoldBuckets
	}
	r.holdMs[ms]++
}

// waitForHoleLocked is the second fix, and the reason the timer semantics
// changed.
//
// 🚨 The first version expired a HELD PACKET and, to release it, declared every
// counter between `next` and that packet lost in one step. With a reorder depth
// of 200-650 that abandoned hundreds of slots at once, and the packets filling
// them — which the input measurement showed arriving only ~15 ms late, far
// inside the hold — then had to be forwarded out of order. That is where
// `late-bypass 212` and an OUTPUT displacement of p50 185 came from: the
// resequencer manufacturing the very disorder it exists to remove.
//
// The deadline belongs to the HOLE, not to the packets queued behind it. One
// missing counter is given up per expiry, and the next hole starts its own
// clock — so a straggler only has to beat holdFor for ITS counter, not for
// whatever happens to be held above it.
func (r *resequencer) waitForHoleLocked(g *generation, now time.Time) {
	if now.Sub(g.holeSince) < r.hold {
		return
	}
	r.timeouts++
	g.next++
	g.holeSince = now
	r.drainLocked(g)
}

// abandonGapLocked is the safety valve: skip straight to the lowest held
// counter. Without it a run of genuinely missing counters would cost holdFor
// EACH, so a client that stops mid-sequence could stall the group for seconds.
func (r *resequencer) abandonGapLocked(g *generation, now time.Time) {
	lowest, first := uint64(0), true
	for c := range g.held {
		if first || c < lowest {
			lowest, first = c, false
		}
	}
	if first {
		return
	}
	if lowest > g.next {
		g.next = lowest
	}
	g.holeSince = now
	r.drainLocked(g)
}

// oldestDeadlineLocked returns the earliest moment at which anything needs
// attention, and whether there is any.
func (r *resequencer) oldestDeadlineLocked() (time.Time, bool) {
	var best time.Time
	found := false
	consider := func(t time.Time) {
		if !found || t.Before(best) {
			best, found = t, true
		}
	}
	for i, g := range r.gens {
		if len(g.held) == 0 && i == 0 {
			continue
		}
		if i == 0 {
			// The hole clock, plus the per-packet safety valve.
			consider(g.holeSince.Add(r.hold))
			for _, h := range g.held {
				consider(h.at.Add(reseqMaxWaitFactor * r.hold))
			}
			continue
		}
		// A newer generation is blocked on the older one closing.
		consider(g.lastSeen.Add(r.hold))
	}
	// The oldest generation closes once it has been quiet for a hold.
	if len(r.gens) > 1 {
		consider(r.gens[0].lastSeen.Add(r.hold))
	}
	return best, found
}

func (r *resequencer) armLocked(now time.Time) {
	deadline, ok := r.oldestDeadlineLocked()
	if !ok {
		r.stopLocked()
		return
	}
	d := deadline.Sub(now)
	// ⚠️ FLOOR, not a rounding convenience. A deadline stuck in the past used to
	// re-arm at 1 ms forever — measured on the device as ~1875 timer firings per
	// second, every one of them taking the mutex that all 30 writers need. The
	// floor bounds what any such bug can cost, and the `valve` counter in
	// conn-stats makes it visible instead of merely slow.
	if d < reseqMinRearm {
		d = reseqMinRearm
	}
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(d, r.onTimeout)
}

func (r *resequencer) stopLocked() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}

func (r *resequencer) onTimeout() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timer = nil
	if len(r.gens) == 0 {
		return
	}
	now := time.Now()

	// A generation older than the current one closes once it has gone quiet;
	// only then may the next one start emitting, which is what preserves order
	// across a rekey.
	for len(r.gens) > 1 && now.Sub(r.gens[0].lastSeen) >= r.hold {
		r.closeOldestLocked()
	}

	g := r.gens[0]
	// Safety valve first: any packet that has waited far too long ends the gap
	// wholesale, so the per-packet bound survives a genuinely missing run.
	for _, h := range g.held {
		if now.Sub(h.at) >= reseqMaxWaitFactor*r.hold {
			r.valves++
			r.abandonGapLocked(g, now)
			break
		}
	}
	r.waitForHoleLocked(g, now)
	r.armLocked(now)
}

// closeOldestLocked flushes the oldest generation in counter order and drops it.
func (r *resequencer) closeOldestLocked() {
	if len(r.gens) == 0 {
		return
	}
	g := r.gens[0]
	keys := make([]uint64, 0, len(g.held))
	for c := range g.held {
		keys = append(keys, c)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, c := range keys {
		h := g.held[c]
		r.recordHold(time.Since(h.at))
		_ = r.writeLocked(h.buf)
	}
	r.gens = r.gens[1:]
	// 🚨 The promoted generation must be DRAINED at once. While it was queued
	// behind an older one every packet was held, including the one equal to its
	// own `next` — so without this its first packet sits below the watermark
	// forever and is stranded. Caught by the rekey-ordering test.
	if len(r.gens) > 0 {
		r.drainLocked(r.gens[0])
	}
}

// writeLocked is the single point where anything reaches WireGuard, which is
// what makes the order this file computes the order WireGuard actually sees.
// The output is measured here too, so the log carries the disorder BEFORE
// (reorder.go, at the merge point) and AFTER on adjacent lines — a fix that
// does not work cannot hide.
func (r *resequencer) writeLocked(pkt []byte) error {
	uplinkReorderOut.observe(pkt, time.Now())
	_, err := r.w.Write(pkt)
	return err
}

func (r *resequencer) passthrough(pkt []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeLocked(pkt)
}

// close releases everything still held, so a group teardown does not swallow
// packets that had already crossed the network.
func (r *resequencer) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.gens) > 0 {
		r.closeOldestLocked()
	}
	r.stopLocked()
}

func (r *resequencer) summaryAndReset() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.total == 0 {
		return ""
	}
	held := r.buffered
	pct := 100 * float64(r.passed) / float64(r.total)
	// 🚨 NORMALISE BY THE HISTOGRAM'S OWN SUM, not by `held`. A packet counts in
	// `buffered` on the way IN and in the histogram on the way OUT, so at every
	// interval boundary the two differ by whatever is still held. Dividing by
	// `held` once printed "p99 512 ms" beside "max 31 ms" — the impossibility
	// is the only reason it was caught. A statistic is normalised by the thing
	// it is a statistic OF.
	var histN int64
	for _, c := range r.holdMs {
		histN += c
	}
	mean := time.Duration(0)
	if histN > 0 {
		mean = time.Duration(r.holdNs / histN)
	}
	s := fmt.Sprintf(
		"  reseq[%s]: %d pkts, %.1f%% already in order, %d held (hold mean %s p50/p90/p99 %d/%d/%d ms max %s over %d released, peak %d), holes %d, valve %d, overflow %d, late-bypass %d, keypairs %d/%d",
		r.name, r.total, pct, held,
		mean.Round(100*time.Microsecond),
		histPct(r.holdMs[:], histN, 0.50), histPct(r.holdMs[:], histN, 0.90), histPct(r.holdMs[:], histN, 0.99),
		r.maxHold.Round(time.Millisecond), histN, r.maxHeldObs,
		r.timeouts, r.valves, r.overflows, r.lateBypass, r.rekeys, len(r.gens))
	r.total, r.passed, r.buffered = 0, 0, 0
	r.timeouts, r.valves, r.overflows, r.lateBypass, r.rekeys = 0, 0, 0, 0, 0
	r.holdNs, r.maxHeldObs, r.maxHold = 0, 0, 0
	for i := range r.holdMs {
		r.holdMs[i] = 0
	}
	return s
}

// resequencers registers every live instance so the conn-stats dump can report
// them without threading a reference through the connection code.
var resequencers = struct {
	mu sync.Mutex
	m  map[*resequencer]struct{}
}{m: map[*resequencer]struct{}{}}

func registerResequencer(r *resequencer) {
	resequencers.mu.Lock()
	resequencers.m[r] = struct{}{}
	resequencers.mu.Unlock()
}

func unregisterResequencer(r *resequencer) {
	resequencers.mu.Lock()
	delete(resequencers.m, r)
	resequencers.mu.Unlock()
}

func dumpResequencers() {
	if uplinkReseqHold <= 0 {
		return
	}
	resequencers.mu.Lock()
	live := make([]*resequencer, 0, len(resequencers.m))
	for r := range resequencers.m {
		live = append(live, r)
	}
	resequencers.mu.Unlock()
	for _, r := range live {
		if s := r.summaryAndReset(); s != "" {
			log.Print(s)
		}
	}
}
