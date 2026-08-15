package srtpwrap

import (
	"log"
	"sync/atomic"
)

// THE DEMUX QUEUE, MADE VISIBLE.
//
// 🎯 WHY THIS EXISTS. On 2026-08-15 the uplink-loss investigation reached a
// hypothesis it could not test: that the loss the server measures is caused by
// the SERVER being busy — a loaded WireGuard back-pressuring us until packets
// are dropped upstream of the point where `reorder.go` counts them. The paced
// synthetic cannot test it, because WireGuard discards its packets at the index
// lookup and they never load it.
//
// 🚨 THE ARCHITECTURE ALREADY BREAKS THAT CHAIN, and this file is the proof
// obligation. `demux` is the ONLY reader of the one UDP socket that carries all
// thirty relay connections, and its hand-off to a session is NON-BLOCKING: a
// slow consumer cannot stall it, so a slow WireGuard cannot make the kernel drop
// on that socket. What a slow consumer CAN do is fill `rtpCh` (4096 packets per
// session) until this demux starts dropping — and THAT drop lands upstream of
// `reorder.go`'s observation point, so it would look exactly like a packet lost
// on the network.
//
// ⚠️ Which makes the drop counter necessary but NOT sufficient: it has been
// silent in every log to date, and a counter that has never fired tells you
// nothing about how close it came. The PEAK DEPTH is the leading indicator, and
// it is what this file adds — the queue at 5% of capacity and the queue at 95%
// are the same silence in the drop counter and completely different states.
//
// ⚠️ Note the asymmetry with `runDemuxFromPacketConn`, the client-side path in
// this same file: that one BLOCKS on a full queue instead of dropping. Do not
// reason about one from the other.

const rtpQueueCap = 4096

var (
	rtpQueuePeak  atomic.Int64
	rtpQueueDrops atomic.Int64
	dtlsDrops     atomic.Int64
)

// noteRTPEnqueued records the queue depth an arriving packet found. Sampling at
// ENQUEUE is deliberate: it measures the depth at the instants that matter —
// when packets are arriving — rather than on a timer that would mostly sample
// the quiet gaps between bursts.
func noteRTPEnqueued(depth int) {
	for {
		old := rtpQueuePeak.Load()
		if int64(depth) <= old || rtpQueuePeak.CompareAndSwap(old, int64(depth)) {
			return
		}
	}
}

// noteRTPDrop counts and logs a packet the demux had to throw away. 🚨 Both
// halves matter: the log line names the session for a human, and the counter
// puts it in the same 2 s dump as the loss it would be mistaken for.
func noteRTPDrop(src interface{}) {
	rtpQueueDrops.Add(1)
	log.Printf("srtpwrap: dropped RTP packet from %v (rtpCh full) — 🚨 this lands "+
		"UPSTREAM of the server's loss counter and is indistinguishable there "+
		"from a packet lost on the network", src)
}

func noteDTLSDrop(src interface{}) {
	dtlsDrops.Add(1)
	log.Printf("srtpwrap: dropped DTLS packet from %v (dtlsCh full)", src)
}

// THE SECOND SILENT DROP, AND IT WAS UNCOUNTED UNTIL 2026-08-15.
//
// 🎯 WHY THIS EXISTS. `wrappedConn.Read` discards a packet on two error paths —
// `DecryptRTP` failing and the RTP header failing to unmarshal — and both were a
// bare `continue`. The loss counter observes in `main.go` AFTER this Read, so a
// packet dropped here is never counted as arrived and appears downstream as a
// GAP IN THE SENDER'S COUNTER SPACE: indistinguishable from a packet lost on the
// network, which is exactly the quantity the uplink-loss investigation is
// measuring. The exclusion "the server is uninvolved" rested on the demux queue
// depth and on netstat, and NEITHER of them covers this path. *(User-raised.)*
//
// ⚠️ A failure here is not automatically OUR bug — a packet corrupted in transit
// fails authentication too, and that IS network loss. What the counters settle
// is which of the two it is, and until they exist the question cannot even be
// asked. Note also that outer replay protection is NOT a candidate: the contexts
// are built by `srtp.CreateContext` with no replay option, so pion's default of
// no replay protection applies.
//
// 🚨 `delivered` is here as the DENOMINATOR. A failure count without it is a
// number nobody can size, and this project has already published one of those.
var (
	unwrapDelivered   atomic.Int64
	unwrapDecryptFail atomic.Int64
	unwrapHeaderFail  atomic.Int64
	unwrapDetailLogs  atomic.Int64
)

// unwrapDetailBudget caps the per-process detail lines. A systematic failure
// would otherwise write one line per packet at thousands per second and bury the
// log that has to be read afterwards; the aggregate carries the rest.
const unwrapDetailBudget = 5

func noteUnwrapDelivered() { unwrapDelivered.Add(1) }

func noteUnwrapDecryptFail(src interface{}, n int, err error) {
	unwrapDecryptFail.Add(1)
	logUnwrapDetail("SRTP decrypt", src, n, err)
}

func noteUnwrapHeaderFail(src interface{}, n int, err error) {
	unwrapHeaderFail.Add(1)
	logUnwrapDetail("RTP header unmarshal", src, n, err)
}

// logUnwrapDetail names the first few failures. The KIND of failure is what
// separates "the wire corrupted it" from "our unwrap is wrong", and an aggregate
// count cannot carry it.
func logUnwrapDetail(what string, src interface{}, n int, err error) {
	if unwrapDetailLogs.Add(1) > unwrapDetailBudget {
		return
	}
	log.Printf("srtpwrap: %s FAILED for a %d-byte packet from %v: %v — 🚨 this packet "+
		"is dropped BEFORE the server's loss counter observes it, so it appears "+
		"downstream as a gap in the sender's counter space and is indistinguishable "+
		"there from network loss (only the first %d such lines are printed)",
		what, n, src, err, unwrapDetailBudget)
}

// UnwrapStats reports and RESETS what the SRTP unwrap delivered and dropped.
func UnwrapStats() (delivered, decryptFail, headerFail int64) {
	return unwrapDelivered.Swap(0), unwrapDecryptFail.Swap(0), unwrapHeaderFail.Swap(0)
}

// QueueStats reports and RESETS the peak depth and the drop counts. Returns the
// capacity too, because a depth without its denominator is not a reading.
func QueueStats() (peak, drops, dtls int64, capacity int) {
	return rtpQueuePeak.Swap(0), rtpQueueDrops.Swap(0), dtlsDrops.Swap(0), rtpQueueCap
}

// NoteRTPDrop and NoteRTPEnqueued are exported for ONE reason: the dump that
// presents these numbers lives in package main, and its tests must be able to
// drive them through the SAME calls the demux makes rather than through a
// parallel fake that could drift from the real path. They are not part of the
// transport API and nothing in the data path should call them.
func NoteRTPDrop(src interface{}) { noteRTPDrop(src) }
func NoteRTPEnqueued(depth int)   { noteRTPEnqueued(depth) }

// Same reason, for the unwrap counters.
func NoteUnwrapDelivered()                              { noteUnwrapDelivered() }
func NoteUnwrapDecryptFail(src interface{}, n int, e error) { noteUnwrapDecryptFail(src, n, e) }
func NoteUnwrapHeaderFail(src interface{}, n int, e error)  { noteUnwrapHeaderFail(src, n, e) }
