package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
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
// NO loss: every one of the 113 retransmissions in the capture was spurious.
// What the shuffle costs is the congestion window — the receiver answers 69.3%
// of its ACKs as duplicate ACKs and the sender never leaves fast-recovery.
//
// WireGuard itself does not care: its replay window is 8128 packets and accepts
// all of this. It also does not FIX it — it hands packets to the TUN in arrival
// order, so the inner TCP inherits the shuffle whole.
//
// THE SHAPE OF THE FIX comes from the measurement, not from taste. The shuffle
// is deep in packets but SHORT IN TIME: lateness p50 0 ms, p90 6 ms, p99 7-16,
// max 35 over a whole run. So a small hold buffer keyed on WireGuard's own
// counter recovers order at a cost of tens of milliseconds, and only for packets
// that actually arrive early — an in-order packet is written through untouched.
//
// 🚨 WHY THIS CANNOT LOSE DATA. Three rules, in order of importance:
//
//  1. A packet is never dropped. One that arrives after its slot was already
//     released is written through immediately, out of order. That is strictly
//     better than dropping it: the hole is already visible to the inner TCP and
//     a late fill is what SACK wants, whereas a drop would manufacture the real
//     loss we have spent two days proving does not exist.
//  2. The wait is bounded by holdFor, and separately by maxHeld packets. Neither
//     bound can be exceeded even if the client stops sending.
//  3. Only transport messages are held. Handshakes carry no counter and are
//     passed straight through — delaying a handshake could break the session,
//     and there are too few of them to matter anyway.
//
// ⚠️ THERE IS A STARTUP TRANSIENT, and it is unavoidable. The first transport
// packet seen defines where the sequence starts, so any packet with a LOWER
// counter that arrives afterwards has missed its slot and is forwarded out of
// order. The transient is bounded by the reorder depth — a couple of dozen
// packets once per keypair — because nothing older than that is still in
// flight. Knowing the true first counter would require state we do not have and
// would buy a few packets at the start of a two-minute epoch.
//
// ⚠️ REKEY. The counter restarts at zero under a new receiver index roughly
// every two minutes. State is therefore keyed by index: a new one flushes what
// is held, in order, and starts a fresh sequence. Sharing state across a rekey
// would read as a four-billion-packet jump backwards.
//
// The resequencer lives on the GROUP's hub, because a group is exactly the set
// of connections that merge. A connection with its own private socket has
// nothing to merge with and is left alone.

const (
	// maxHeld bounds both memory and the damage a stuck sequence can do. At the
	// measured p99 depth of ~320 packets this is generous; when it is hit the
	// oldest gap is abandoned immediately rather than waiting for holdFor.
	reseqMaxHeld = 2048
)

// uplinkReseqHold is the hold timer. Zero disables the resequencer entirely,
// which is the default — this is a treatment, and a run without it is the
// control that says whether it did anything.
var uplinkReseqHold time.Duration

// resequencer restores counter order for one group of connections.
type resequencer struct {
	mu   sync.Mutex
	w    io.Writer
	name string

	idx     uint32 // receiver index of the keypair being tracked
	haveIdx bool
	next    uint64 // the counter we are waiting for
	held    map[uint64][]byte
	heldAt  map[uint64]time.Time // arrival time, so the mean hold is measured
	timer   *time.Timer

	// Interval counters, read and reset by the conn-stats dump.
	total      int64 // transport packets seen
	passed     int64 // already in order, written straight through
	buffered   int64 // held at least momentarily
	timeouts   int64 // gaps abandoned because holdFor expired
	overflows  int64 // gaps abandoned because maxHeld was reached
	lateBypass int64 // arrived after its slot was released — written anyway
	holdNs     int64 // total time packets spent held
	maxHeldObs int
}

func newResequencer(w io.Writer, name string) *resequencer {
	return &resequencer{
		w: w, name: name,
		held:   map[uint64][]byte{},
		heldAt: map[uint64]time.Time{},
	}
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

	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++

	if !r.haveIdx || r.idx != idx {
		// New keypair. Flush what is held for the old one, in order, then start
		// this sequence at the counter in hand.
		r.flushAllLocked()
		r.idx, r.haveIdx = idx, true
		r.next = ctr
	}

	switch {
	case ctr < r.next:
		// Its slot is gone. Forward rather than drop — see rule 1.
		r.lateBypass++
		return r.writeLocked(pkt)

	case ctr == r.next:
		r.passed++
		if err := r.writeLocked(pkt); err != nil {
			return err
		}
		r.next++
		r.drainLocked()
		return nil
	}

	// Early: hold it until the gap fills, the timer fires, or the buffer fills.
	r.buffered++
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	if _, dup := r.held[ctr]; !dup {
		r.heldAt[ctr] = time.Now()
	}
	r.held[ctr] = cp
	if n := len(r.held); n > r.maxHeldObs {
		r.maxHeldObs = n
	}
	if len(r.held) > reseqMaxHeld {
		r.overflows++
		r.skipToLowestLocked()
	}
	r.armLocked()
	return nil
}

// drainLocked releases every packet that has become contiguous.
func (r *resequencer) drainLocked() {
	for {
		buf, ok := r.held[r.next]
		if !ok {
			return
		}
		if t, ok := r.heldAt[r.next]; ok {
			r.holdNs += int64(time.Since(t))
			delete(r.heldAt, r.next)
		}
		delete(r.held, r.next)
		_ = r.writeLocked(buf)
		r.next++
	}
}

// skipToLowestLocked abandons the current gap: it advances to the lowest held
// counter and drains from there. The abandoned packets are not lost — they were
// never received.
func (r *resequencer) skipToLowestLocked() {
	lowest := uint64(0)
	first := true
	for c := range r.held {
		if first || c < lowest {
			lowest, first = c, false
		}
	}
	if first {
		return
	}
	r.next = lowest
	r.drainLocked()
}

func (r *resequencer) flushAllLocked() {
	for len(r.held) > 0 {
		r.skipToLowestLocked()
	}
	r.stopLocked()
}

// armLocked keeps exactly one pending timer while anything is held.
func (r *resequencer) armLocked() {
	if r.timer != nil || len(r.held) == 0 {
		return
	}
	r.timer = time.AfterFunc(uplinkReseqHold, r.onTimeout)
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
	if len(r.held) == 0 {
		return
	}
	r.timeouts++
	r.skipToLowestLocked()
	r.armLocked()
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

// close releases anything still held, so a group teardown does not swallow
// packets that had already crossed the network.
func (r *resequencer) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushAllLocked()
}

func (r *resequencer) summaryAndReset() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.total == 0 {
		return ""
	}
	held := r.buffered
	pct := 100 * float64(r.passed) / float64(r.total)
	mean := time.Duration(0)
	if held > 0 {
		mean = time.Duration(r.holdNs / held)
	}
	s := fmt.Sprintf(
		"  reseq[%s]: %d pkts, %.1f%% already in order, %d held (mean %s, peak %d), timeouts %d, overflow %d, late-bypass %d",
		r.name, r.total, pct, held, mean.Round(100*time.Microsecond), r.maxHeldObs,
		r.timeouts, r.overflows, r.lateBypass)
	r.total, r.passed, r.buffered = 0, 0, 0
	r.timeouts, r.overflows, r.lateBypass = 0, 0, 0
	r.holdNs, r.maxHeldObs = 0, 0
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
