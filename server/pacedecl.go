package main

import (
	"encoding/binary"
	"sync/atomic"
)

// THE CLIENT'S PACE DECLARATION (2026-11-07, the user's design).
//
// The downlink pacer (pacer.go) shapes every grouped connection to
// -downlink-pace, a number measured against VK's per-allocation policer. A
// connection that rides the user's OWN relay has no such policer, and there the
// pacer is pure cost: Nov 4 §561–§562 measured the own relay's download at
// 74 Mbit/s under it and 104–135 without. Which relay a connection rides is
// something this server cannot know — it sees the address a connection comes
// from and nothing behind it, and a list of VK's relay networks is not ours to
// keep. The CLIENT knows: its override list names each relay with its pace
// (host:port:quota:pace), and it declares the pace of a connection's relay
// right behind the hello that groups the connection:
//
//	0xff 'P' 'A' 'C' + rate (KiB/s of counted bytes, two big-endian bytes;
//	0 = no pacer) + zeros to the hello's 20 bytes
//
// — the hello's construction, so a server that predates this forwards it to
// WireGuard, which drops it as malformed, and an old client that sends none
// runs at the flag's rate as before.
//
// Why the client's word is trusted: a declaration changes the pacing of the
// declaring connection and nothing else. A VK relay declared unpaced loses
// ~10 % of its downlink to VK's policer — that client's loss, nobody else's;
// no other tenant's share moves. The pacer protects the client from VK, not
// the server from the client, so the party that bears the cost decides.
// -downlink-pace-max is the operator's bound on top: a declared rate above it
// is the cap, and "no pacer" becomes the cap; 0 (the default) honours the
// declaration as made.
var groupPaceMagic = []byte{0xff, 'P', 'A', 'C'}

// downlinkPaceMax: the highest pace a client may declare, in counted bytes
// per second; 0 = no cap. Set once from main, read-only after.
var downlinkPaceMax float64

// isGroupPace reports whether buf is a pace declaration and returns its rate
// in KiB/s. Exact length, like the hello and the supersede sentinel: nothing
// else may be mistaken for it, or a WireGuard packet would be swallowed.
func isGroupPace(buf []byte) (kib uint16, ok bool) {
	if len(buf) != groupHelloLen {
		return 0, false
	}
	for i, b := range groupPaceMagic {
		if buf[i] != b {
			return 0, false
		}
	}
	return binary.BigEndian.Uint16(buf[4:6]), true
}

// declarePace records the client's declaration for this connection; true
// when it changed the connection's rate (the first word, or a different one).
// The generation moves with every change so the writer can tell (paceRate).
func (st *connStat) declarePace(kib uint16) bool {
	next := int64(kib) + 1 // 0 = undeclared
	if st.paceDecl.Swap(next) == next {
		return false
	}
	st.paceGen.Add(1)
	return true
}

// declaredPace: the client's declaration, ok false = none.
func (st *connStat) declaredPace() (kib uint16, ok bool) {
	v := st.paceDecl.Load()
	if v == 0 {
		return 0, false
	}
	return uint16(v - 1), true
}

// paceRate is the rate and burst this connection's writer paces at — the
// declaration under the cap, else the flags' — and the declaration's
// generation, so serveConn rebuilds its bucket when the word changes. The
// burst is the flag's; with the flag off (its burst 0) a declared rate gets a
// bucket that holds one maximum-size packet, or every write would stall.
func (st *connStat) paceRate() (rate, burst float64, gen uint64) {
	gen = st.paceGen.Load()
	burst = downlinkPaceBurst
	if burst < pacerMaxCost {
		burst = pacerMaxCost
	}
	kib, ok := st.declaredPace()
	if !ok {
		return downlinkPaceRate, burst, gen
	}
	rate = float64(kib) * 1024
	if downlinkPaceMax > 0 && (rate == 0 || rate > downlinkPaceMax) {
		rate = downlinkPaceMax
	}
	return rate, burst, gen
}

// paceDeclState is the pair connStat keeps: the declaration (0 = none, else
// KiB + 1) and its generation.
type paceDeclState struct {
	paceDecl atomic.Int64
	paceGen  atomic.Uint64
}

// describePaceKiB / describePaceRate spell a declaration and the rate it
// resolves to for the log.
func describePaceKiB(kib uint16) string {
	if kib == 0 {
		return "no pacer"
	}
	return humanBytes(int64(kib)*1024) + "/s"
}

func describePaceRate(rate float64) string {
	if rate <= 0 {
		return "unpaced"
	}
	return "at " + humanBytes(int64(rate)) + "/s"
}
