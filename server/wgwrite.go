package main

import (
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/server/srtpwrap"
)

// HOW LONG THE SERVER HOLDS A PACKET BETWEEN THE RELAY AND WIREGUARD.
//
// 🎯 THE QUESTION. The uplink loss the server measures is counted at the merge
// point, BEFORE the packet is handed to WireGuard — so a packet WireGuard drops
// has already been counted as arrived and cannot appear as a gap. The only way
// a busy server could produce those gaps is by back-pressure reaching far
// enough upstream to make something drop BEFORE that point, and this file plus
// `srtpwrap.QueueStats` are the two halves of measuring that:
//
//	relay ──UDP──▶ [one socket, one demux goroutine] ──▶ rtpCh ──▶ pump ──▶ WG
//	                        ↑ kernel drops here            ↑ demux drops here
//	                        (netstat, host-wide)           (srtpwrap counter)
//
// 🚨 The hand-off into `rtpCh` is NON-BLOCKING, so a slow pump cannot stall the
// demux and cannot make the kernel drop. It can only fill `rtpCh` until the
// demux drops — which is counted. This instrument measures the pump's own delay
// so that "the queue is filling" has a cause attached to it rather than being
// an unexplained number.
//
// ⚠️ WHAT A LARGE VALUE HERE DOES AND DOES NOT MEAN. `wg.Write` goes to a
// loopback UDP socket: it does not wait for WireGuard to process anything, so
// it should be microseconds and a large value means the local socket is
// congested, not that WireGuard is slow. WireGuard being slow shows up as
// KERNEL DROPS on its own receive socket (netstat's full-socket-buffer counter
// on port 51820), which is a different line entirely. Do not read this one as a
// measure of WireGuard's speed.
//
// ⚠️ And when the resequencer is on, the write goes through it instead, so the
// number then includes its hold. Run measurements with `-uplink-reseq=0`.

// Bucket edges. The first three are where a healthy loopback write lives; the
// last two exist because the question is whether it EVER stalls, and a
// histogram that tops out below the interesting value answers nothing.
var wgWriteEdges = [...]time.Duration{
	50 * time.Microsecond,
	200 * time.Microsecond,
	time.Millisecond,
	5 * time.Millisecond,
	20 * time.Millisecond,
}

var (
	wgWriteBuckets [len(wgWriteEdges) + 1]atomic.Int64
	wgWriteCount   atomic.Int64
	wgWriteMaxNs   atomic.Int64
)

// observeWGWrite files one hand-off duration.
func observeWGWrite(d time.Duration) {
	wgWriteCount.Add(1)
	i := 0
	for i < len(wgWriteEdges) && d >= wgWriteEdges[i] {
		i++
	}
	wgWriteBuckets[i].Add(1)
	for {
		old := wgWriteMaxNs.Load()
		if int64(d) <= old || wgWriteMaxNs.CompareAndSwap(old, int64(d)) {
			return
		}
	}
}

// wgWritePctile reads a percentile off the histogram as the LOWER edge of the
// bucket it lands in, so p50 <= p90 <= p99 <= max holds mechanically.
func wgWritePctile(counts []int64, total int64, q float64) time.Duration {
	if total == 0 {
		return 0
	}
	target := int64(float64(total) * q)
	var c int64
	for i := range counts {
		c += counts[i]
		if c > target {
			if i == 0 {
				return 0
			}
			return wgWriteEdges[i-1]
		}
	}
	return wgWriteEdges[len(wgWriteEdges)-1]
}

// dumpWGWriteAndReset prints the hand-off delay beside the demux queue it
// feeds, and clears both. 🚨 They are printed on ONE line on purpose: the delay
// is only interesting as an explanation for the depth, and the depth is only
// interesting as a distance from the drop.
func dumpWGWriteAndReset() {
	total := wgWriteCount.Swap(0)
	counts := make([]int64, len(wgWriteBuckets))
	for i := range wgWriteBuckets {
		counts[i] = wgWriteBuckets[i].Swap(0)
	}
	maxD := time.Duration(wgWriteMaxNs.Swap(0))
	peak, drops, dtls, capacity := srtpwrap.QueueStats()
	// 🚨 Read UNCONDITIONALLY, before the silence check below: these are
	// read-and-reset counters, so a dump that returns early without reading them
	// would carry an interval's failures into the next interval's numbers.
	delivered, decFail, hdrFail := srtpwrap.UnwrapStats()

	if total == 0 && peak == 0 && drops == 0 && dtls == 0 && delivered == 0 && decFail == 0 && hdrFail == 0 {
		// Silence rather than a row of zeros: an instrument that prints zeros
		// when it has nothing cannot be told from one that measured zero.
		return
	}

	// THE SRTP UNWRAP, on its own line because it is a different story: not how
	// long we held a packet, but whether we silently threw it away upstream of
	// the loss counter. ⚠️ The zeros here are PRINTED whenever traffic flowed —
	// that is the point, since this line exists to turn "we never looked" into
	// "we looked and it was zero".
	if delivered > 0 || decFail > 0 || hdrFail > 0 {
		unwrapNote := ""
		if decFail > 0 || hdrFail > 0 {
			unwrapNote = fmt.Sprintf(" 🚨 %.4f%% of arrivals DROPPED IN OUR UNWRAP — these are "+
				"counted downstream as network loss",
				100*float64(decFail+hdrFail)/float64(delivered+decFail+hdrFail))
		}
		log.Printf("  srtp-unwrap: %d delivered, %d decrypt-fail, %d header-fail%s",
			delivered, decFail, hdrFail, unwrapNote)
	}

	note := ""
	if drops > 0 || dtls > 0 {
		note = fmt.Sprintf(" 🚨 DROPPED %d RTP / %d DTLS — these land UPSTREAM of "+
			"the loss counter and are indistinguishable there from network loss", drops, dtls)
	}
	log.Printf("  wg-write: %d writes p50 %s p90 %s p99 %s max %s | demux rtpq peak %d/%d (%.1f%%)%s",
		total,
		wgWritePctile(counts, total, 0.50).Round(time.Microsecond),
		wgWritePctile(counts, total, 0.90).Round(time.Microsecond),
		wgWritePctile(counts, total, 0.99).Round(time.Microsecond),
		maxD.Round(time.Microsecond),
		peak, capacity, 100*float64(peak)/float64(capacity), note)
}
