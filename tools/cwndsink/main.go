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
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("listen", ":5202", "listen address (bind so the WG tunnel IP reaches it)")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("cwndsink: listen %s: %v", *addr, err)
	}
	log.Printf("cwndsink: listening on %s — draining, reporting delivered goodput/s", *addr)

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
			// never rwnd-limited — otherwise a small default window reintroduces
			// the 64 KB rig trap and caps the sender's flight below its cwnd.
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetReadBuffer(8 << 20)
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
