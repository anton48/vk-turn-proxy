package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// wgPkt builds a minimal WireGuard transport message: type 4, the given
// receiver index and counter, and enough tail to be a plausible packet.
func wgPkt(idx uint32, ctr uint64) []byte {
	b := make([]byte, 64)
	b[0] = wgMsgTypeTransport
	binary.LittleEndian.PutUint32(b[4:8], idx)
	binary.LittleEndian.PutUint64(b[8:16], ctr)
	return b
}

func newStats() *reorderStats {
	reorderStatsEnabled = true
	return &reorderStats{peers: map[uint32]*peerSeq{}}
}

// sendRun delivers counters [0,n) in order except for `hole`, which is left
// out so it can arrive late afterwards.
//
// ⚠️ The hole is load-bearing and my first draft of these tests lacked it. If
// counter 20 has already been delivered, sending it again is DUPLICATION and
// the tracker is right to say so — the test failed, the code did not. Leaving
// the hole is the only way to construct a genuinely late packet.
func sendRun(s *reorderStats, idx uint32, n, hole uint64, at time.Time) {
	for i := uint64(0); i < n; i++ {
		if i == hole {
			continue
		}
		s.observe(wgPkt(idx, i), at)
	}
}

// A stream that arrives in the order it was sent must report nothing. This is
// the negative result the whole instrument rests on: if it cannot report zero,
// a non-zero reading means nothing either.
func TestInOrderStreamReportsNoReordering(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	for i := uint64(0); i < 5000; i++ {
		s.observe(wgPkt(7, i), base.Add(time.Duration(i)*time.Millisecond))
	}
	if s.displaced != 0 {
		t.Fatalf("in-order stream reported %d displaced packets, want 0", s.displaced)
	}
	if s.dup != 0 || s.stale != 0 {
		t.Fatalf("in-order stream reported dup=%d stale=%d, want 0/0", s.dup, s.stale)
	}
	if s.total != 5000 {
		t.Fatalf("total = %d, want 5000", s.total)
	}
}

// Displacement must be the exact distance below the running maximum, not an
// estimate — this is the whole reason for reading WireGuard's counter instead
// of inferring from TCP mid-path, where tshark reported 47% against a true
// 1.24%.
func TestDisplacementDepthIsExact(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	// Send 0..99 in order, then deliver 100 late by exactly 40, 20 and 5.
	for i := uint64(0); i < 100; i++ {
		s.observe(wgPkt(1, i), base)
	}
	s.observe(wgPkt(1, 200), base) // max jumps to 200
	for _, d := range []uint64{40, 20, 5} {
		s.observe(wgPkt(1, 200-d), base)
	}
	if s.displaced != 3 {
		t.Fatalf("displaced = %d, want 3", s.displaced)
	}
	if s.maxDepth != 40 {
		t.Fatalf("maxDepth = %d, want 40", s.maxDepth)
	}
	for _, d := range []int{5, 20, 40} {
		if s.depth[d] != 1 {
			t.Fatalf("depth bucket %d = %d, want 1", d, s.depth[d])
		}
	}
	if got := histPct(s.depth[:], s.displaced, 0.50); got != 20 {
		t.Fatalf("p50 depth = %d, want 20", got)
	}
}

// 🚨 The trap this instrument exists to avoid. A rekey restarts the counter at
// zero under a NEW receiver index; keyed on the index that is a fresh sequence,
// but a tracker keyed on the peer alone would see a jump of billions backwards
// and report a catastrophe that never happened.
func TestRekeyIsNotReordering(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	for i := uint64(0); i < 1000; i++ {
		s.observe(wgPkt(0xAAAA, i), base)
	}
	// New keypair: new index, counter back to 0.
	for i := uint64(0); i < 1000; i++ {
		s.observe(wgPkt(0xBBBB, i), base)
	}
	if s.displaced != 0 {
		t.Fatalf("rekey reported %d displaced packets, want 0", s.displaced)
	}
	if s.rekeys != 2 {
		t.Fatalf("keypairs = %d, want 2", s.rekeys)
	}
}

// A duplicate is duplication, not lateness. Conflating the two is exactly what
// made the first reading of the server2 capture wrong by a factor of 38.
func TestDuplicateIsNotCountedAsReordering(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	sendRun(s, 3, 50, 20, base)   // 0..49 with 20 missing
	s.observe(wgPkt(3, 20), base) // genuinely late
	s.observe(wgPkt(3, 20), base) // the same packet again — duplication
	if s.displaced != 1 {
		t.Fatalf("displaced = %d, want 1", s.displaced)
	}
	if s.dup != 1 {
		t.Fatalf("dup = %d, want 1", s.dup)
	}
}

// Beyond the window we cannot tell a duplicate from a very late packet, so it
// must be reported as its own category rather than silently folded into either.
func TestBeyondWindowIsReportedAsStale(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	s.observe(wgPkt(4, 0), base)
	s.observe(wgPkt(4, reorderDupWindow*3), base)
	s.observe(wgPkt(4, 1), base) // far outside the window now
	if s.stale != 1 {
		t.Fatalf("stale = %d, want 1", s.stale)
	}
	if s.displaced != 0 {
		t.Fatalf("displaced = %d, want 0 — a stale packet is not a measured displacement", s.displaced)
	}
}

// Lateness is time since the MAXIMUM was seen, which is the quantity that
// decides whether the receiver's loss detector fires — not time since the
// previous packet.
func TestLatenessIsMeasuredAgainstTheMaximum(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	s.observe(wgPkt(9, 100), base)
	s.observe(wgPkt(9, 90), base.Add(37*time.Millisecond))
	if s.late[37] != 1 {
		t.Fatalf("late bucket 37ms = %d, want 1", s.late[37])
	}
	if s.maxLate != 37*time.Millisecond {
		t.Fatalf("maxLate = %s, want 37ms", s.maxLate)
	}
}

func TestHandshakesAndRunts(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	for _, typ := range []byte{1, 2, 3} { // handshake init / response / cookie
		p := wgPkt(1, 5)
		p[0] = typ
		s.observe(p, base)
	}
	s.observe(make([]byte, wgTransportHdrLen-1), base) // too short to be one
	s.observe(nil, base)
	if s.total != 0 {
		t.Fatalf("total = %d, want 0 — only transport messages carry a counter", s.total)
	}
}

// The counters are read-and-reset, so a second consumer would steal from the
// first. Pin that they clear, and that the sequence state SURVIVES the reset —
// clearing it would restart every peer's maximum and manufacture reordering.
func TestDumpResetsCountersButKeepsSequences(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	sendRun(s, 2, 100, 50, base)  // 0..99 with 50 missing
	s.observe(wgPkt(2, 50), base) // arrives late, depth 49

	line := s.summaryLocked()
	if !strings.Contains(line, "reorder(uplink)") || !strings.Contains(line, "100 pkts") {
		t.Fatalf("summary line looks wrong: %q", line)
	}
	if !strings.Contains(line, "1.0% out-of-order") {
		t.Fatalf("summary line lost the displacement: %q", line)
	}
	s.dumpAndReset(base)
	if s.total != 0 || s.displaced != 0 || s.maxDepth != 0 {
		t.Fatalf("counters not reset: total=%d displaced=%d maxDepth=%d", s.total, s.displaced, s.maxDepth)
	}
	if got := s.summaryLocked(); got != "" {
		t.Fatalf("empty interval produced a line: %q", got)
	}

	// ⚠️ The sequence must SURVIVE, and the assertion has to be one that a wipe
	// actually breaks. My first attempt asserted "the next packet is not
	// displaced" — a wiped map passes that trivially, because the peer is
	// recreated with the new counter as its maximum. Sabotaging the code proved
	// the test toothless. The signal a wipe cannot fake is the KEYPAIR COUNT:
	// an existing peer must not be re-created.
	p := s.peers[2]
	if p == nil || p.max != 99 {
		t.Fatalf("sequence state lost across the dump: peer=%v", p)
	}
	s.observe(wgPkt(2, 100), base)
	if s.rekeys != 0 {
		t.Fatalf("keypairs = %d after the dump, want 0 — the peer was re-created", s.rekeys)
	}
	if s.displaced != 0 {
		t.Fatalf("packet 100 read as displaced against max 99")
	}
}

func TestDisabledIsInert(t *testing.T) {
	s := newStats()
	reorderStatsEnabled = false
	defer func() { reorderStatsEnabled = true }()
	s.observe(wgPkt(1, 5), time.Unix(0, 0))
	if s.total != 0 {
		t.Fatalf("total = %d with the flag off, want 0", s.total)
	}
}

// Idle keypairs must be dropped or a long-lived server accumulates 1 KB of ring
// per rekey — roughly 720 of them a day per client.
func TestIdlePeersArePruned(t *testing.T) {
	s := newStats()
	base := time.Unix(0, 0)
	s.observe(wgPkt(1, 0), base)
	s.observe(wgPkt(2, 0), base.Add(reorderPeerIdle+time.Second))
	s.dumpAndReset(base.Add(reorderPeerIdle + 2*time.Second))
	if _, alive := s.peers[1]; alive {
		t.Fatalf("idle keypair 1 was not pruned")
	}
	if _, alive := s.peers[2]; !alive {
		t.Fatalf("active keypair 2 was pruned")
	}
}
