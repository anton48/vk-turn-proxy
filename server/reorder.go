package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// Uplink reorder measurement — how badly the client's 30 connections shuffle
// one inner flow on its way to WireGuard.
//
// WHY THIS EXISTS. A capture on server2 during an upload burst (2026-08-09,
// N=30, 21.3 Mbit/s up) found ZERO real loss — every one of the 113
// retransmissions was spurious, the data had already arrived — but 74.2% of
// inner TCP segments arrived OUT OF ORDER, median displacement 14 segments,
// and 69.3% of the receiver's ACKs were duplicate ACKs. The inner TCP therefore
// never leaves fast-recovery: its congestion window is shut by phantom loss we
// manufacture ourselves. Median displacement ≈ N/2 at N=30 is the signature of
// striping one flow across N paths of unequal latency, which is exactly what
// per-packet work-stealing across the client's connections does.
//
// That capture measured the EFFECT, one hop downstream and in TCP's sequence
// space. This measures the CAUSE, in place, at the point where the connections
// merge — and it lives in the same file region as the eventual fix, so the same
// instrument that names the problem will show whether the fix worked.
//
// WHY WIREGUARD'S COUNTER AND NOT A CAPTURE. A packet capture on the phone is
// useless here: on the wire everything is inside SRTP+DTLS+WireGuard and would
// need three decryptors. But a WireGuard TRANSPORT message carries its 64-bit
// counter IN THE CLEAR — it is the AEAD nonce, so it has to be readable — and
// the counter is strictly increasing at the sender by construction. That makes
// displacement EXACT rather than heuristic.
//
//	byte 0     : message type, 4 = transport data
//	bytes 1-3  : reserved
//	bytes 4-7  : receiver index (LE) — assigned by US, changes on every rekey
//	bytes 8-15 : counter (LE)        — strictly increasing per keypair
//
// 🚨 Contrast with the tool we used first: tshark, reading mid-path, reported
// 47.4% "retransmission" and 4205 "fast retransmissions" where the truth was
// 113 duplicates, because it cannot tell a late segment from a resent one. This
// tracker never has to guess — a counter it has already seen is a duplicate, a
// counter below the maximum is late, and nothing else is possible.
//
// ⚠️ REKEY IS NOT REORDERING. WireGuard rotates keypairs roughly every 2
// minutes and the counter restarts at 0. Keying the state by RECEIVER INDEX
// makes that a new sequence rather than a 4-billion-packet backwards jump; the
// rekey count is reported so an implausible statistic can be checked against it.
//
// Multiple clients need no special handling: distinct peers hold distinct
// receiver indices, so each gets its own sequence. The histograms aggregate,
// which is what we want — the question is about the construct, not the client.

const (
	wgMsgTypeTransport = 4
	wgTransportHdrLen  = 16 // type(1) + reserved(3) + receiver(4) + counter(8)

	// Displacement is exact below this and lands in one overflow bucket above
	// it. The worst displacement seen in the server2 capture was 340 packets,
	// so 1024 leaves a wide margin at 8 KB of counters.
	reorderDepthBuckets = 1024
	// Lateness in whole milliseconds, same shape. The capture's p99 was 47 ms.
	reorderLateBuckets = 512

	// Duplicate-detection window, in packets. Deliberately the same 8128 as
	// wireguard-go's own replay window (replay.windowSize = 127*64): a duplicate
	// too old for WireGuard to reject is also too old for us to care about.
	reorderDupWindow = 8128

	// Peers with no traffic for this long are dropped, so a long-lived server
	// does not accumulate state for old keypairs.
	reorderPeerIdle = 5 * time.Minute
)

// peerSeq tracks one keypair's counter sequence.
type peerSeq struct {
	max   uint64    // highest counter seen
	maxAt time.Time // when it was seen — lateness is measured against this
	seen  []uint64  // bitmap ring over (max-reorderDupWindow, max]
	last  time.Time // for idle pruning
}

func newPeerSeq(now time.Time) *peerSeq {
	return &peerSeq{seen: make([]uint64, reorderDupWindow/64), last: now}
}

// mark records counter c in the ring and reports whether it was already there.
// Counters more than reorderDupWindow behind the maximum cannot be answered and
// return stale=true.
func (p *peerSeq) mark(c uint64) (dup bool, stale bool) {
	if c > p.max {
		// Advancing: clear the bits the window slides over, so a counter from a
		// previous lap cannot masquerade as a duplicate.
		gap := c - p.max
		if gap >= reorderDupWindow {
			for i := range p.seen {
				p.seen[i] = 0
			}
		} else {
			for x := p.max + 1; x <= c; x++ {
				idx := x % reorderDupWindow
				p.seen[idx/64] &^= 1 << (idx % 64)
			}
		}
		idx := c % reorderDupWindow
		p.seen[idx/64] |= 1 << (idx % 64)
		return false, false
	}
	if p.max-c >= reorderDupWindow {
		return false, true
	}
	idx := c % reorderDupWindow
	if p.seen[idx/64]&(1<<(idx%64)) != 0 {
		return true, false
	}
	p.seen[idx/64] |= 1 << (idx % 64)
	return false, false
}

type reorderStats struct {
	mu    sync.Mutex
	peers map[uint32]*peerSeq

	total     int64 // transport packets observed
	displaced int64 // counter below the maximum, and genuinely not a duplicate
	dup       int64 // counter seen before — duplication, NOT reordering
	stale     int64 // too far behind to classify
	rekeys    int64 // new receiver index, i.e. a fresh keypair

	depth    [reorderDepthBuckets + 1]int64
	late     [reorderLateBuckets + 1]int64
	maxDepth uint64
	maxLate  time.Duration
}

// uplinkReorder is the single instance, observed from every connection's
// inbound goroutine and read only by the conn-stats dump. One consumer, because
// the counters are read-and-reset and two readers would steal from each other.
var uplinkReorder = &reorderStats{peers: map[uint32]*peerSeq{}}

// reorderStatsEnabled gates the whole thing so a run can be done without it as
// a control. On by default: the cost is one map lookup and a few bit operations
// per uplink packet.
var reorderStatsEnabled = true

// observe records one packet on its way from a client connection to WireGuard.
// Non-transport messages (handshakes) carry no counter and are ignored; so are
// short buffers, which cannot be transport messages at all.
func (s *reorderStats) observe(pkt []byte, now time.Time) {
	if !reorderStatsEnabled || len(pkt) < wgTransportHdrLen || pkt[0] != wgMsgTypeTransport {
		return
	}
	idx := binary.LittleEndian.Uint32(pkt[4:8])
	ctr := binary.LittleEndian.Uint64(pkt[8:16])

	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.peers[idx]
	if p == nil {
		p = newPeerSeq(now)
		p.max, p.maxAt = ctr, now
		s.peers[idx] = p
		s.rekeys++
		s.total++
		_, _ = p.mark(ctr)
		return
	}
	p.last = now
	s.total++

	dup, stale := p.mark(ctr)
	switch {
	case dup:
		// A duplicate is duplication, not reordering. Counting it as displaced
		// is exactly the conflation that made tshark report 47% where the truth
		// was 1.24%.
		s.dup++
		return
	case stale:
		s.stale++
		return
	}
	if ctr > p.max {
		p.max, p.maxAt = ctr, now
		return
	}

	d := p.max - ctr
	s.displaced++
	if d > s.maxDepth {
		s.maxDepth = d
	}
	if d > reorderDepthBuckets {
		s.depth[reorderDepthBuckets]++
	} else {
		s.depth[d]++
	}

	late := now.Sub(p.maxAt)
	if late > s.maxLate {
		s.maxLate = late
	}
	ms := int(late / time.Millisecond)
	if ms < 0 {
		ms = 0
	}
	if ms > reorderLateBuckets {
		ms = reorderLateBuckets
	}
	s.late[ms]++
}

// histPct returns the value at the given fraction of a histogram, or -1 when
// the histogram is empty.
//
// ⚠️ Nearest-rank, with the rank ROUNDED UP. Truncating instead puts p50 of
// three samples on the smallest of them — the caught-in-review case was
// depths {5, 20, 40} reporting a median of 5. The error shrinks with sample
// size but never becomes right, and a diagnostic that lies on small intervals
// is worse than none: short intervals are exactly what a burst gets.
func histPct(h []int64, total int64, frac float64) int {
	if total == 0 {
		return -1
	}
	want := int64(math.Ceil(frac * float64(total)))
	if want < 1 {
		want = 1
	}
	var seen int64
	for i, c := range h {
		seen += c
		if seen >= want {
			return i
		}
	}
	return len(h) - 1
}

// dumpAndReset writes one summary line and clears the interval counters. The
// per-peer sequence state is NOT cleared — it is the running sequence, not a
// statistic — except for peers that have gone idle.
func (s *reorderStats) dumpAndReset(now time.Time) {
	if !reorderStatsEnabled {
		return
	}
	s.mu.Lock()
	line := s.summaryLocked()
	s.total, s.displaced, s.dup, s.stale, s.rekeys = 0, 0, 0, 0, 0
	s.maxDepth, s.maxLate = 0, 0
	for i := range s.depth {
		s.depth[i] = 0
	}
	for i := range s.late {
		s.late[i] = 0
	}
	for idx, p := range s.peers {
		if now.Sub(p.last) > reorderPeerIdle {
			delete(s.peers, idx)
		}
	}
	s.mu.Unlock()
	if line != "" {
		log.Print(line)
	}
}

// summaryLocked builds the report. Caller holds s.mu.
func (s *reorderStats) summaryLocked() string {
	if s.total == 0 {
		return ""
	}
	share := 100 * float64(s.displaced) / float64(s.total)
	dh, lh := s.depth[:], s.late[:]
	return fmt.Sprintf(
		"  reorder(uplink): %d pkts, %.1f%% out-of-order, depth p50/p90/p99/max %d/%d/%d/%d, late p50/p90/p99 %d/%d/%d ms (max %s), dup %d, stale %d, keypairs %d",
		s.total, share,
		histPct(dh, s.displaced, 0.50), histPct(dh, s.displaced, 0.90), histPct(dh, s.displaced, 0.99), s.maxDepth,
		histPct(lh, s.displaced, 0.50), histPct(lh, s.displaced, 0.90), histPct(lh, s.displaced, 0.99),
		s.maxLate.Round(time.Millisecond),
		s.dup, s.stale, s.rekeys)
}
