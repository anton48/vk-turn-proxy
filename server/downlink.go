package main

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// downlinkHub — M1 of the downlink-scheduler plan, behind -single-client.
//
// THE PROBLEM. By default pumpBidirectional dials its OWN UDP socket toward
// -connect for every accepted connection, so the local WireGuard sees N
// distinct sources for one peer. A WireGuard peer holds exactly ONE endpoint
// and rewrites it from the last received batch (device/receive.go:515,
// unconditional; SendBuffers reads a single peer.endpoint.val). Whatever
// delivered most recently therefore receives 100% of the return traffic, and
// nothing schedules the split. Measured on the phone: the downlink comes out
// 6.5-9.1x uneven while the uplink is 1.1-1.4x, and the hottest connection
// sits at 85-103% of its ~2.07 Mbit/s per-allocation policer — which is what
// caps download at ~25 Mbit/s against ~62 available.
//
// THE FIX. One socket to WireGuard, so the peer endpoint is stable, plus an
// explicit shared queue that every connection's writer drains. Work-stealing
// rather than round-robin, deliberately: a connection that is slow simply
// takes fewer packets, and routing around a slow connection is precisely the
// failure being fixed. This mirrors the client's own uplink (one sendCh, all
// conns stealing from it).
//
// ⚠️ CORRECT FOR ONE CLIENT ONLY. Connections are not grouped by client here,
// so with two clients connected the return traffic of one would be sprayed
// across the other's connections and lost — the other client's WireGuard
// rejects it on the keypair. That is why this is a default-off experiment
// flag and not the shipping behaviour; grouping by an explicit client hello
// is M3 of the plan.
const (
	dlBufSize = 1600
	// dlQueueSize mirrors the client's sendCh depth. The send into this queue
	// BLOCKS rather than dropping, same policy as the uplink: back-pressure
	// belongs in the kernel's socket buffer, not in silent packet loss.
	dlQueueSize = 256
)

// 🎯 THE ACK-PATH EXPERIMENT (-downlink-small-conns / -downlink-small-size).
//
// WHY. Upload sits at ~23 Mbit/s while download does ~57 through the same 30
// connections. As of 2026-08-11 reordering is REFUTED as the cause, twice over:
// resequencing the uplink to 0.00% residual disorder left the aggregate
// unmoved (18.1 vs 18.3), and the client-side instrument then showed the
// DOWNLINK is MORE disordered than the uplink (83.8% vs 78-80%, depth p50 18
// vs 15-19) while carrying 2.4x the throughput. Disorder of the DATA is
// survivable; that is now measured in both directions.
//
// What that run also measured for the first time is the other stream: during an
// upload the downlink carries nothing but ACKs, and those arrive at the phone
// **71-75% out of order**, depth p50 8-11. TCP is ACK-clocked. A sender whose
// ACK return path is shuffled by our own 30-way work-stealing loses its clock
// even when its data arrives fine — and this is the one asymmetry that inverts
// with direction: uploading, the ACKs come DOWN this hub; downloading, they go
// UP the client's unpaced uplink.
//
// WHAT THIS DOES. Route packets at or below dlSmallSize — bare ACKs, which are
// ~84-145 B once WireGuard's 32 B are added — onto a small subset of
// connections instead of spraying them across all 30, and serve them in
// preference to data on those connections.
//
// ⚠️ Why a SUBSET and not one connection. During the measured upload the ACK
// stream was ~1600 pkt/s at ~150 counted B = ~240 KB/s, and the per-allocation
// policer knee is 247-260 KiB/s. Pinning every ACK to a single connection would
// park it AT the knee, where §2g measured a ~4.6x loss amplification. Two to
// four connections keep each well under it while cutting the fan-out that
// creates the disorder by an order of magnitude. Sweep N — do not assume 1.
//
// 🚫 This is NOT the qWDTT ACK-priority channel the plan forbids copying. That
// prohibition exists because on the CLIENT an ACK-priority path pins WireGuard's
// single peer endpoint and collapses the downlink onto one allocation. This is
// the SERVER's downlink, after M3 gave every group one socket to WireGuard;
// nothing here selects a peer endpoint. The prohibition's premise does not apply
// — verified before writing this, not assumed.
var (
	// dlSmallConns is how many connections carry the small-packet path.
	// 0 = off, which is byte-for-byte today's behaviour.
	dlSmallConns = 0
	// dlSmallSize is the size at or below which a packet takes that path, in
	// bytes as read off the WireGuard socket. A bare ACK is 52-72 B of inner
	// packet (+ up to 40 B of SACK/timestamp options) plus WireGuard's 32, so
	// 160 catches ACKs including SACK-heavy ones and cannot catch a 1312 B data
	// packet. Raise it only with a reason: the wider it is, the more this
	// becomes "pin some data to a few conns", which is a different experiment.
	dlSmallSize = 160
)

// Counters for the small path, read-and-reset by the conn-stats dump.
//
// ⚠️ These aggregate across groups. The experiment is single-client, so that is
// fine here; if it ever runs with two clients connected, read them as a total
// and not as one client's behaviour.
var (
	dlSmallRouted   atomic.Int64 // packets that took the small path
	dlSmallFellBack atomic.Int64 // wanted it, queue was full, went to the main queue
	dlSmallWriters  atomic.Int32 // connections currently serving it
)

// enqueueSmall routes p onto the ACK path if it qualifies and there is room,
// reporting whether it took it. It NEVER blocks: a full small queue, or every
// small-serving connection dying at once, must degrade to today's behaviour
// rather than stall the whole downlink behind a queue nobody is draining.
func (h *downlinkHub) enqueueSmall(p dlPacket) bool {
	if dlSmallConns <= 0 || p.n > dlSmallSize || dlSmallWriters.Load() == 0 {
		return false
	}
	select {
	case h.smallCh <- p:
		dlSmallRouted.Add(1)
		return true
	default:
		dlSmallFellBack.Add(1)
		return false
	}
}

// claimSmallSlot takes one of the dlSmallConns writer slots if any is free.
//
// CAS rather than a bare Add: thirty connections start within a couple of
// hundred milliseconds of each other, and two of them believing they got the
// last slot widens the fan-out this experiment exists to narrow — by exactly
// the amount that would never be noticed in the output.
func claimSmallSlot() bool {
	if dlSmallConns <= 0 {
		return false
	}
	for {
		cur := dlSmallWriters.Load()
		if cur >= int32(dlSmallConns) {
			return false
		}
		if dlSmallWriters.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// dlReadBuffer is the hub socket's SO_RCVBUF, set from -downlink-rcvbuf.
//
// ❌ DEFAULT IS OFF, AND THAT IS A MEASURED RESULT, not an oversight. Enlarging
// this buffer looked obviously right — the OS default is 42080 B on FreeBSD and
// one wireguard-go batch is ~168 KiB, so a single batch cannot fit. It was
// tested at 1 MiB against the default, back to back, same pacer rate:
//
//	                   Recv-Q max   udp drops   ΣDOWN steady   speedtest ⬇   loaded ⬇ ping
//	OS default 42 KiB       41728     +64803    59.33 Mbit/s     58.1          299 ms
//	1 MiB                  904704     +41114    59.33 Mbit/s     55.2          488 ms
//
// Throughput did not move — the PACER sets the rate, not the buffer, and
// delivery was ~100% either way. What the extra megabyte bought was 122 ms of
// standing queue and ~190 ms of loaded latency. A shallow buffer here is doing
// the job of an AQM: the inner TCP offers more than the paced rate, the excess
// has to be dropped somewhere, and dropping it early beats delaying everything.
// (One upload in the 1 MiB run collapsed to 0.36 Mbit/s. n=1, but the mechanism
// is plausible — the phone's upload ACKs ride this same queue.)
var dlReadBuffer = 0

// dlPool keeps the per-packet buffers off the heap. Not premature: this
// project has already lost a week to a GC death-spiral caused by per-packet
// allocation on a hot receive path (iOS build 146).
var dlPool = sync.Pool{
	New: func() any {
		b := make([]byte, dlBufSize)
		return &b
	},
}

type dlPacket struct {
	buf *[]byte
	n   int
}

type downlinkHub struct {
	wg net.Conn
	ch chan dlPacket
	// smallCh carries the ACK-sized packets when -downlink-small-conns is set.
	// Always allocated so the routing code needs no nil check on a hot path.
	smallCh chan dlPacket
	reseq   *resequencer // nil unless -uplink-reseq is set
}

// label identifies the GROUP in this hub's log lines. Every group dials the same
// -connect address, so naming the resequencer after that address made two
// clients' rekeys indistinguishable — which defeats the point of logging them.
func newDownlinkHub(ctx context.Context, connect, label string) (*downlinkHub, error) {
	c, err := net.Dial("udp", connect)
	if err != nil {
		return nil, err
	}
	// The hub reads EVERY connection's downlink through this one socket, so the
	// OS default receive buffer is far too shallow for it.
	//
	// Measured 2026-08-08 on the FreeBSD server during a paced run: Recv-Q on
	// this socket peaked at 41168 B against a net.inet.udp.recvspace default of
	// 42080 — 97.8% full — while udp "dropped due to full socket buffers" rose
	// by 28196 over the same window. The arithmetic says it cannot be otherwise:
	// wireguard-go writes in batches of up to 128 packets, so ONE batch of
	// 1312 B packets is ~168 KiB, four times the default buffer. Those drops
	// land BEFORE st.down.Add, so they are invisible to the delivered-vs-offered
	// ratio that says 100%.
	//
	// ⚠️ Bigger is not simply better: this queue drains at the paced rate, so
	// buffer beyond a few batches only converts loss into latency. The default
	// here is ~6 batches; the kernel may clamp it (FreeBSD: kern.ipc.maxsockbuf).
	// Both branches log, including the do-nothing one: this flag defaults to ON,
	// so a log with no line about the receive buffer would be ambiguous between
	// "old binary" and "control run" months from now.
	if uc, ok := c.(*net.UDPConn); !ok {
		log.Printf("downlink hub: not a UDP socket, receive buffer left alone")
	} else if dlReadBuffer <= 0 {
		log.Printf("downlink hub: receive buffer left at the OS default " +
			"(-downlink-rcvbuf 0) — CONTROL for the buffer experiment; expect " +
			"udp 'dropped due to full socket buffers' to climb under load")
	} else if err := uc.SetReadBuffer(dlReadBuffer); err != nil {
		log.Printf("downlink hub: SetReadBuffer(%d) failed, keeping the OS "+
			"default: %s", dlReadBuffer, err)
	} else {
		log.Printf("downlink hub: read buffer requested %d KiB (the kernel "+
			"may clamp this — FreeBSD: sysctl kern.ipc.maxsockbuf)",
			dlReadBuffer/1024)
	}
	h := &downlinkHub{
		wg:      c,
		ch:      make(chan dlPacket, dlQueueSize),
		smallCh: make(chan dlPacket, dlQueueSize),
	}
	// The resequencer belongs to the GROUP, because a group is exactly the set
	// of connections that merge — and merging unequal-latency paths is what
	// shuffles the uplink. A connection on its own private socket has nothing to
	// merge with and never gets one.
	if uplinkReseqHold > 0 {
		h.reseq = newResequencer(c, label, uplinkReseqHold)
		registerResequencer(h.reseq)
		log.Printf("downlink hub %s: uplink resequencer on, hold %s — measured "+
			"optimum is 150ms, where residual output disorder first reads 0.00%%; "+
			"below it the resequencer manufactures disorder (30ms leaves 11.3%%)",
			label, uplinkReseqHold)
	}
	context.AfterFunc(ctx, func() {
		if h.reseq != nil {
			// Flush before the socket goes: packets held here have already
			// crossed the network and dropping them would manufacture the loss
			// this whole change exists to avoid.
			h.reseq.close()
			unregisterResequencer(h.reseq)
		}
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	})
	go h.readLoop(ctx)
	return h, nil
}

// readLoop is the single reader of the shared WireGuard socket. Everything it
// reads is fanned out to whichever connection writer is free.
func (h *downlinkHub) readLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		p := dlPool.Get().(*[]byte)
		_ = h.wg.SetReadDeadline(time.Now().Add(30 * time.Minute))
		n, err := h.wg.Read(*p)
		if err != nil {
			dlPool.Put(p)
			if ctx.Err() == nil {
				log.Printf("downlink hub: read from WireGuard failed: %s", err)
			}
			return
		}
		if h.enqueueSmall(dlPacket{buf: p, n: n}) {
			continue
		}
		select {
		case h.ch <- dlPacket{buf: p, n: n}:
		case <-ctx.Done():
			dlPool.Put(p)
			return
		}
	}
}

// serveConn is one connection's share of the return path: steal a packet from
// the shared queue, write it out. Returns when the connection dies or the
// context is cancelled — the hub itself outlives individual connections.
//
// When -downlink-pace is set every write is first charged to a per-connection
// token bucket (see pacer.go), so the connection emits at the rate VK will
// actually carry rather than as fast as the WireGuard socket produces.
func (h *downlinkHub) serveConn(ctx context.Context, conn net.Conn, st *connStat) {
	var pc *pacer
	if downlinkPaceRate > 0 {
		pc = newPacer(downlinkPaceRate, downlinkPaceBurst)
	}
	serveSmall := claimSmallSlot()
	if serveSmall {
		defer dlSmallWriters.Add(-1)
	}
	for {
		// Reserve BEFORE dequeuing — see the warning on pacer.await. A writer
		// waiting on tokens must not be holding a packet that a connection with
		// tokens could have sent.
		var waited time.Duration
		if pc != nil {
			var ok bool
			waited, ok = pc.await(ctx, pacerMaxCost)
			if !ok {
				return
			}
		}
		var p dlPacket
		if serveSmall {
			// Strict preference for the ACK-sized queue on this connection: try
			// it first, and only block on both when it is empty. Data cannot
			// starve, because the blocking select still offers h.ch.
			select {
			case p = <-h.smallCh:
			default:
				select {
				case <-ctx.Done():
					if pc != nil {
						pc.refund(pacerMaxCost)
					}
					return
				case p = <-h.smallCh:
				case p = <-h.ch:
				}
			}
		} else {
			select {
			case <-ctx.Done():
				if pc != nil {
					pc.refund(pacerMaxCost)
				}
				return
			case p = <-h.ch:
			}
		}
		{
			n := p.n
			if pc != nil {
				// Give back what this packet did not need. The reservation was
				// for a maximum-size packet; most are smaller.
				pc.refund(pacerMaxCost - float64(n+pacerPerPacketOverhead))
			}
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
			_, err := conn.Write((*p.buf)[:n])
			dlPool.Put(p.buf)
			if err != nil {
				log.Printf("downlink write failed: %s", err)
				return
			}
			st.down.Add(int64(n))
			st.downPkts.Add(1)
			// Charge the wait to the SAME packet as the byte count, and only
			// once the write has happened. Counting it back at await() time
			// instead let a dump land between the wait and the write, so up to
			// one in-flight packet per connection was counted as delayed but
			// not as written — which printed "8024/7999 writes delayed
			// (100.3%)" in the first production run and reads like a bug.
			if waited > 0 {
				st.pacedNs.Add(int64(waited))
				st.pacedPkts.Add(1)
			}
		}
	}
}
