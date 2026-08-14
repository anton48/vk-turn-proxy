// cwndsink — a plain TCP discard sink for the iOS uplink cwnd probe (M0).
//
// It must run at the FAR END OF WIREGUARD, i.e. behind WG decryption, NOT inside
// the SRTP server (which sits BEFORE WG). Put it on the WG host — e.g. bound so
// the WG tunnel address 192.168.102.1 reaches it — so the app's inner TCP flows
// terminate here after: relay -> server1 SRTP unwrap -> WG :51820 decrypt ->
// this listener. That way the reordering under study (the 30-conn fan-out
// re-converging at server1) is on the path, and nothing else is.
//
// The probe reads snd_cwnd on the PHONE; this side only has to drain fast enough
// never to be the bottleneck. The per-second delivered figure is a cross-check
// (offered on the phone vs delivered here / vs server1 ΣUP).
//
//   go run ./tools/cwndsink -listen :5202
//   # equivalent drain without stats:  nc -lk 5202 >/dev/null
package main

import (
	"flag"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// 🚨 THE RECEIVE WINDOW IS THIS SINK'S MOST DANGEROUS PROPERTY, AND IT LIED FOR
// FIVE DEVICE SESSIONS. On 2026-08-14 a capture showed the advertised window
// PINNED at 65 728 bytes — p05 60 864, p50 = p90 = p99 = max = 65 728, never
// growing — which at srtt 118 ms bounds every inner flow at window/RTT =
// 4.46 Mbit/s. F=4 is then bounded at 17.8 Mbit/s, and the runs measured
// 16.3-17.2: the probe was reading THIS PROGRAM, not the tunnel. `winuse 3%` on
// the phone was the signature all along (cwnd 33x in-flight, because in-flight
// is pinned by the receiver).
//
// The old code asked for 8 MiB and IGNORED THE ERROR, under a comment that
// named "the 64 KB rig trap" — so the guard against the trap is what re-created
// it. On FreeBSD (this host) SO_RCVBUF is bounded by kern.ipc.maxsockbuf and a
// request above it FAILS with ENOBUFS rather than being clamped, and an explicit
// SO_RCVBUF also turns OFF the socket's SB_AUTOSIZE. Either way the outcome is
// the same shape: a silently unchanged 64 KB default.
//
// So this no longer asks once and hopes. It walks DOWN a ladder until the
// kernel accepts a size, READS BACK what it actually got, and LOGS it with the
// per-flow bound it implies. An instrument that cannot report its own ceiling
// has no business being the thing everything else is measured against.
//
// If nothing on the ladder is accepted, that is fine and is logged as such: a
// failed SO_RCVBUF leaves auto-sizing ON, which is the better outcome anyway.
// Sysctls that decide the ceiling on FreeBSD:
//
//	kern.ipc.maxsockbuf          hard cap on any SO_RCVBUF request
//	net.inet.tcp.recvbuf_auto    1 = auto-sizing on (leave it on)
//	net.inet.tcp.recvbuf_max     how far auto-sizing may grow
//	net.inet.tcp.recvspace       the default this was stuck at (65 536)
var rcvbufOnce sync.Once

// rcvbufLadder is walked from the top down. 8 MiB at a 120 ms RTT is ~560
// Mbit/s per flow, far past anything this path can do; the small end exists so
// a conservative kern.ipc.maxsockbuf still gets us off the 64 KB default.
var rcvbufLadder = []int{8 << 20, 4 << 20, 2 << 20, 1 << 20, 512 << 10, 256 << 10}

// reportRecvBufCeiling walks the same ladder on a THROWAWAY socket at startup
// and logs what the kernel will grant, so the ceiling is known BEFORE a run
// rather than after its first packet.
//
// 🚨 That ordering is the whole lesson of 2026-08-14: the per-connection line
// below would have exposed the 64 KB window too, but only once traffic was
// already flowing — and a ceiling discovered after the fact costs the run. On
// FreeBSD the effective cap is kern.ipc.maxsockbuf ADJUSTED DOWN for mbuf
// overhead (sb_max_adj ~ sb_max * MCLBYTES/(MSIZE+MCLBYTES)), so a request for
// exactly maxsockbuf is expected to fail and the ladder to settle one rung
// lower. That is fine; what matters is that the number is printed.
func reportRecvBufCeiling() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Printf("cwndsink: ⚠️ could not probe the SO_RCVBUF ceiling: %v", err)
		return
	}
	defer syscall.Close(fd)
	want := 0
	for _, size := range rcvbufLadder {
		if syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size) == nil {
			want = size
			break
		}
	}
	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		log.Printf("cwndsink: ⚠️ could not read back SO_RCVBUF: %v", err)
		return
	}
	mbit := float64(got) * 8 / 0.120 / 1e6
	note := ""
	if mbit < 50 {
		note = "  🚨 THIS BOUNDS EACH FLOW BELOW THE TUNNEL — raise kern.ipc.maxsockbuf"
	}
	log.Printf("cwndsink: receive-window ceiling %d bytes (largest of the ladder accepted: %d) "+
		"= ~%.0f Mbit/s per flow at 120 ms RTT%s", got, want, mbit, note)
}

// tuneRecvBuf enlarges the socket's receive buffer and reports what the kernel
// actually granted. Returns the effective SO_RCVBUF, or 0 if it could not be
// read.
func tuneRecvBuf(tc *net.TCPConn) (want, got int, err error) {
	for _, size := range rcvbufLadder {
		if e := tc.SetReadBuffer(size); e == nil {
			want = size
			break
		} else {
			err = e
		}
	}
	// Read back rather than trust the request: the number that matters is the
	// one the kernel kept, and on some systems it is not the one we asked for.
	if raw, e := tc.SyscallConn(); e == nil {
		_ = raw.Control(func(fd uintptr) {
			if v, e2 := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF); e2 == nil {
				got = v
			}
		})
	}
	return want, got, err
}

func main() {
	addr := flag.String("listen", ":5202", "listen address (bind so the WG tunnel IP reaches it)")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("cwndsink: listen %s: %v", *addr, err)
	}
	log.Printf("cwndsink: listening on %s — draining, reporting delivered goodput/s", *addr)
	// Before anything connects: state the ceiling this instrument imposes.
	reportRecvBufCeiling()

	var total, conns int64

	go func() {
		var last int64
		for range time.NewTicker(time.Second).C {
			now := atomic.LoadInt64(&total)
			log.Printf("delivered %6.2f Mbit/s  (conns=%d, cum=%.1f MiB)",
				float64(now-last)*8/1e6, atomic.LoadInt64(&conns), float64(now)/(1<<20))
			last = now
		}
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("cwndsink: accept: %v", err)
			continue
		}
		atomic.AddInt64(&conns, 1)
		go func(c net.Conn) {
			defer c.Close()
			defer atomic.AddInt64(&conns, -1)
			// Advertise a large receive window so the SENDER stays cwnd-limited,
			// never rwnd-limited. 🚨 Read the block comment at the top of this
			// file before touching this: the previous version of these three
			// lines is what made every F<=8 probe number a measurement of this
			// program's own 64 KB window.
			if tc, ok := c.(*net.TCPConn); ok {
				want, got, err := tuneRecvBuf(tc)
				rcvbufOnce.Do(func() {
					// One line per RUN, not per connection — but it must be
					// LOUD, because a silent ceiling here invalidates every
					// per-flow number taken through this sink.
					switch {
					case got == 0:
						log.Printf("cwndsink: ⚠️ SO_RCVBUF could not be read back "+
							"(requested %d, last error %v) — per-flow numbers from "+
							"this run are UNVERIFIED", want, err)
					default:
						// The bound a receive window imposes is window/RTT. At the
						// ~120 ms this path runs at, print it in the units the
						// experiment is scored in so nobody has to do the sum.
						mbit := float64(got) * 8 / 0.120 / 1e6
						note := ""
						if mbit < 50 {
							note = "  🚨 THIS BOUNDS EACH FLOW BELOW THE TUNNEL — raise " +
								"kern.ipc.maxsockbuf / net.inet.tcp.recvbuf_max"
						}
						log.Printf("cwndsink: SO_RCVBUF effective %d bytes (requested %d) "+
							"= ~%.0f Mbit/s per flow at 120 ms RTT%s", got, want, mbit, note)
					}
				})
			}
			buf := make([]byte, 1<<16)
			for {
				// Idle reaper: when a probe run's tunnel COLLAPSES (e.g. F=64
				// wedges the phone's networking), the client's FIN never
				// arrives, so Read would block forever and the conn count would
				// leak (stuck at 64, then 72 on the next run). Drop a connection
				// that has gone silent for 15 s.
				_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
				n, err := c.Read(buf)
				atomic.AddInt64(&total, int64(n))
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						log.Printf("cwndsink: reaping idle conn (no data 15 s)")
					}
					return
				}
			}
		}(c)
	}
}
