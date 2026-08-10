package main

import (
	"context"
	"log"
	"net"
	"sync"
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
	wg    net.Conn
	ch    chan dlPacket
	reseq *resequencer // nil unless -uplink-reseq is set
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
	h := &downlinkHub{wg: c, ch: make(chan dlPacket, dlQueueSize)}
	// The resequencer belongs to the GROUP, because a group is exactly the set
	// of connections that merge — and merging unequal-latency paths is what
	// shuffles the uplink. A connection on its own private socket has nothing to
	// merge with and never gets one.
	if uplinkReseqHold > 0 {
		h.reseq = newResequencer(c, label, uplinkReseqHold)
		registerResequencer(h.reseq)
		log.Printf("downlink hub %s: uplink resequencer on, hold %s (measured "+
			"lateness p90 was 6 ms, p99 7-16 ms, max 35 ms)", label, uplinkReseqHold)
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
		select {
		case <-ctx.Done():
			if pc != nil {
				pc.refund(pacerMaxCost)
			}
			return
		case p := <-h.ch:
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
