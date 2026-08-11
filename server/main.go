package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"

	"github.com/cacggghp/vk-turn-proxy/server/srtpwrap"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	useSrtp := flag.Bool("srtp", false,
		"enable SRTP listener mode (accepts DTLS-SRTP from clients running "+
			"the SRTP-wrap transport; deployed as port :56004 separately from "+
			"the legacy :56000 DTLS+WG listener). When set, the listener "+
			"terminates DTLS-SRTP sessions, decrypts RTP-wrapped payload, "+
			"and forwards the inner bytes to -connect (typically a local "+
			"WireGuard instance). Mutually exclusive with the default DTLS "+
			"listener and with -wrap-srtp — pick one mode per server instance.")
	useWrapSrtp := flag.Bool("wrap-srtp", false,
		"enable WRAP+SRTP-mimic listener mode (accepts DTLS+WG inside an "+
			"SRTP-shaped envelope from clients with useWrap=true and "+
			"matching -wrap-key). Same intent as -srtp — bypass VK's content "+
			"classifier — but uses the legacy DTLS+WG inner layer wrapped in "+
			"a static-key ChaCha20-Poly1305 SRTP envelope, allowing a A/B "+
			"comparison against the real DTLS-SRTP path. Mutually exclusive "+
			"with -srtp.")
	wrapKey := flag.String("wrap-key", "",
		"32-byte hex key for -wrap-srtp mode (64 hex chars). Generate one "+
			"with -gen-wrap-key. MUST match the client's wrap_key_hex value "+
			"exactly — wrong keys produce AEAD-open failures on every packet "+
			"and the handshake never completes.")
	genWrapKey := flag.Bool("gen-wrap-key", false,
		"print a freshly generated 32-byte WRAP key as a 64-char hex string "+
			"to stdout and exit. Use the output as both -wrap-key (server) "+
			"and wrap_key_hex (client backup JSON / Settings UI).")
	singleClient := flag.Bool("single-client", false,
		"treat connections that send NO group hello as ONE client: they share "+
			"a single socket toward -connect with a scheduled return path, "+
			"instead of each dialling its own. Clients new enough to send a "+
			"hello are grouped by their own session id and never need this. "+
			"⚠️ CORRECT FOR ONE SUCH CLIENT ONLY — with two hello-less clients "+
			"connected, the return traffic of one is sprayed across the "+
			"other's connections and dropped by its WireGuard on the keypair. "+
			"Default off; on a shared server, leave it off and let grouping do "+
			"the work.")
	rcvBuf := flag.Int("downlink-rcvbuf", dlReadBuffer/1024,
		"receive buffer for the shared -single-client socket, in KiB. 0 "+
			"(default) keeps the OS default. ❌ RAISING THIS WAS TESTED AND "+
			"REJECTED: at 1 MiB against FreeBSD's 42080 B default, same pacer "+
			"rate back to back, throughput did not change at all (steady ΣDOWN "+
			"59.33 Mbit/s both, delivery ~100% both) while loaded download "+
			"latency went 299 -> 488 ms and the speedtest fell 58.1 -> 55.2. "+
			"The pacer sets the rate; the buffer only decides whether the "+
			"excess is dropped early or delayed. Kept as a flag so the result "+
			"can be re-checked, not because it should be on.")
	paceRate := flag.Float64("downlink-pace", defaultPaceKiB,
		"shape each GROUPED connection's downlink to this many KiB/s of COUNTED "+
			"WIRE BYTES — payload plus ~30 B/packet, which is the unit VK's "+
			"per-allocation policer actually meters, so the same number is "+
			"correct at any MTU. 0 disables pacing. ⚠️ Disabling is NOT "+
			"neutral: an unpaced connection offers more than VK will carry, "+
			"11.9% of measured samples land above the cap, and its token bucket "+
			"drops ~10% of the downlink — worth about 16% of throughput. The "+
			"default sits just under a knee that was measured, not fitted: at "+
			"247 delivery is 100.00% and at 260 it is 97.96% with 9.4% less "+
			"throughput. Read the 'pacer:' line in conn-stats — 0 delayed "+
			"writes means the rate is too high to be shaping anything.")
	paceBurst := flag.Float64("downlink-pace-burst", 16,
		"bucket capacity for -downlink-pace, in KiB of counted bytes. This is "+
			"how much overshoot survives the pacer, so it is the whole point: "+
			"too large and nothing is smoothed. 16 KiB is ~64 ms at the "+
			"suggested rate. Ignored when -downlink-pace is 0.")
	smallConns := flag.Int("downlink-small-conns", 0,
		"route ACK-sized downlink packets over this many connections instead of "+
			"work-stealing them across all of them. 0 = off = today's behaviour. "+
			"THE EXPERIMENT (2026-08-11): reordering of the DATA is refuted as the "+
			"upload limiter — the downlink is more disordered than the uplink "+
			"(83.8% vs 78-80%) and carries 2.4x the throughput — but during an "+
			"upload the ACKs coming down this hub are 71-75% out of order, and TCP "+
			"is ACK-clocked. Sweep 1/2/4 against 0, back to back in one session. "+
			"⚠️ Do not assume 1 is best: the measured ACK stream is ~240 KB/s "+
			"against a 247-260 KiB/s per-allocation knee, so a single connection "+
			"would sit AT the knee where 4.5% more offer costs 9.4% of throughput.")
	smallSize := flag.Int("downlink-small-size", dlSmallSize,
		"size in bytes at or below which a downlink packet takes the "+
			"-downlink-small-conns path, measured as read off the WireGuard "+
			"socket. A bare ACK is 84-145 B with WireGuard's 32 included; a data "+
			"packet is ~1344. Widening this past ~200 stops testing the ACK path "+
			"and starts pinning data, which is a different experiment.")
	statsInterval := flag.Duration("conn-stats-interval", connStatsInterval,
		"how often to dump the per-connection UP/DOWN table. The 60s default "+
			"is fine for a running server, but a speedtest alternates download, "+
			"upload and idle inside one interval, so per-connection SHARES "+
			"computed over 60s are not the shares during the download burst. "+
			"Drop this to 2s-5s when measuring, and read the logged KB/s "+
			"directly rather than deriving rates from shares.")
	reorderStats := flag.Bool("reorder-stats", true,
		"measure how badly the client's connections deliver its uplink out of "+
			"order, using WireGuard's cleartext per-packet counter, and report "+
			"it alongside conn-stats. This is the CAUSE of the upload problem "+
			"measured on 2026-08-09: zero real loss but 74% of inner TCP "+
			"segments arriving displaced, so the inner TCP sits in permanent "+
			"fast-recovery. Costs a map lookup and a few bit operations per "+
			"uplink packet; turn it off only to run a control.")
	reseqHold := flag.Duration("uplink-reseq", 0,
		"put the client's uplink back in COUNTER order before WireGuard sees "+
			"it, holding an out-of-order packet up to this long for the gap "+
			"ahead of it to fill. 0 = off, which is the default and the control. "+
			"The client stripes one inner flow across N connections of unequal "+
			"latency, so 73-86% of packets arrive displaced (median depth ~N/2) "+
			"with ZERO loss — and the inner TCP reads that as loss, answers 69% "+
			"of its ACKs as duplicates and never leaves fast-recovery. SIZE IT "+
			"FROM THE DISPLACEMENT DEPTH, NOT FROM THE 'late' FIGURE: depth p90 "+
			"is 280-340 packets, which at ~1300 pkt/s is 230-265 ms of stream, "+
			"and 150ms is the measured point where residual output disorder "+
			"first reaches 0.00%. A SHORTER hold is actively harmful — 30ms "+
			"leaves 11.3% of the output still displaced and manufactures bursts "+
			"of late releases. Nothing is ever dropped: a packet whose slot has "+
			"already been released is forwarded late rather than discarded.")
	logFile := flag.String("logfile", "",
		"if set, append log output to this file instead of stdout. The "+
			"file is opened in append mode (O_APPEND|O_CREATE) so logs from "+
			"multiple restarts accumulate. Both the standard log.* calls and "+
			"the startup banner go through the same writer.")
	flag.Parse()
	reorderStatsEnabled = *reorderStats
	uplinkReseqHold = *reseqHold

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open logfile %q: %v", *logFile, err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Utility mode: print a key and exit. Runs before -connect validation
	// so admins can generate keys on a fresh box without a -connect target.
	if *genWrapKey {
		k, err := genWrapKeyHex()
		if err != nil {
			log.Fatalf("gen-wrap-key: %v", err)
		}
		// Print to STDOUT directly (not log.Printf) so the key is on its
		// own line without timestamp / log prefix — pipeable into config.
		fmt.Println(k)
		return
	}

	// Mode flags are mutually exclusive — guard up front before any
	// listener allocation. The default (neither flag set) is legacy DTLS.
	if *useSrtp && *useWrapSrtp {
		log.Fatalf("server: -srtp and -wrap-srtp are mutually exclusive")
	}

	wrapKeyBytes, err := decodeWrapKey(*useWrapSrtp, *wrapKey)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}

	// M2b: the downlink pacer. It applies to GROUPED connections only — the
	// per-conn path deliberately ignores it. Without a shared queue there is no
	// work-stealing, so a uniform per-connection rate would throttle the one hot
	// connection while its packets queued in its own private socket; nothing
	// would move to the idle connections and the result would be added latency
	// rather than shaping.
	if *paceRate > 0 {
		downlinkPaceRate = *paceRate * 1024
		downlinkPaceBurst = *paceBurst * 1024
		if downlinkPaceBurst < pacerMaxCost {
			// A bucket smaller than one maximum-size packet can never fill
			// enough to send one, and every write would stall forever.
			downlinkPaceBurst = pacerMaxCost
			log.Printf("⚠️  -downlink-pace-burst raised to %.0f B: it must hold "+
				"at least one maximum-size packet", downlinkPaceBurst)
		}
		log.Printf("downlink pacing: %.0f KiB/s of counted bytes per connection "+
			"(payload + %d B/packet), burst %.0f KiB. Watch the 'pacer:' line "+
			"in conn-stats — 0 delayed writes means it is inert.",
			downlinkPaceRate/1024, pacerPerPacketOverhead, downlinkPaceBurst/1024)
	} else {
		// log.Print, not Printf: the percent signs below are literal.
		log.Print("⚠️  downlink pacing is OFF (-downlink-pace 0). Grouped " +
			"connections will offer more than VK carries; ~10% of the downlink " +
			"is expected to be dropped by its policer, costing roughly 16% of " +
			"throughput. This is a deliberate setting, not a default.")
	}

	// M0: per-conn byte counters, always on, no behaviour change.
	if *statsInterval > 0 {
		connStatsInterval = *statsInterval
	}
	statsDone := make(chan struct{})
	defer close(statsDone)
	go runConnStatsLoop(statsDone)

	// M1+M3: the shared-socket downlink scheduler. Hubs are now created on
	// demand, one per client group, so nothing is allocated here — a client
	// that sends a group hello gets a scheduled downlink automatically, and one
	// that does not keeps its own socket.
	if *rcvBuf >= 0 {
		dlReadBuffer = *rcvBuf * 1024
	}
	if *smallConns > 0 {
		dlSmallConns, dlSmallSize = *smallConns, *smallSize
		log.Printf("🎯 ACK-path experiment ON: downlink packets ≤ %d B go over "+
			"%d connection(s) with priority instead of being work-stolen across "+
			"all of them. Read the `small-path:` line in conn-stats — 0 routed "+
			"means nothing was small enough and the run tested nothing.",
			dlSmallSize, dlSmallConns)
	}
	if *singleClient {
		log.Printf("⚠️  -single-client is ON: connections that send NO group "+
			"hello share one socket to %s instead of each dialling its own. "+
			"This is CORRECT ONLY while exactly ONE such client is connected — "+
			"clients new enough to send a hello are grouped properly and do not "+
			"need it.", *connect)
	}

	switch {
	case *useSrtp:
		runSRTPListener(ctx, addr, *connect, *singleClient)
	case *useWrapSrtp:
		runWrapSRTPListener(ctx, addr, *connect, wrapKeyBytes, *singleClient)
	default:
		runDTLSListener(ctx, addr, *connect, *singleClient)
	}
}

// runDTLSListener is the legacy listener mode — accepts DTLS sessions
// directly and pumps decrypted bytes to/from the -connect target. This
// is what the unmodified pre-2026-05-20 server was always doing.
func runDTLSListener(ctx context.Context, addr *net.UDPAddr, connect string, singleClient bool) {
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	log.Printf("Listening (DTLS mode) on %s", addr)

	wg1 := sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			wg1.Wait()
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				wg1.Wait()
				return
			}
			log.Println(err)
			continue
		}
		wg1.Add(1)
		go func(conn net.Conn) {
			defer wg1.Done()
			defer conn.Close()
			log.Printf("Connection from %s\n", conn.RemoteAddr())

			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error")
				cancel1()
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Println(err)
				cancel1()
				return
			}
			cancel1()
			log.Println("Handshake done")

			pumpBidirectional(ctx, conn, connect, singleClient)
		}(conn)
	}
}

// runWrapSRTPListener is the WRAP+SRTP-mimic mode. Mirrors
// runDTLSListener's accept loop but inserts the SRTP-shaped envelope
// (see wrap.go) between UDP and DTLS — so the wire pattern matches
// VK's classifier expectation for RTP media while the inner DTLS+WG
// flow remains identical to the legacy mode. Compatible client is
// iOS app with useWrap=true and matching wrap_key_hex.
func runWrapSRTPListener(ctx context.Context, addr *net.UDPAddr, connect string, key []byte, singleClient bool) {
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	wrapListener, err := listenWrapped(addr, key)
	if err != nil {
		panic(err)
	}
	listener, err := dtls.NewListener(wrapListener, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	log.Printf("Listening (WRAP+SRTP-mimic mode) on %s", addr)

	wg1 := sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			wg1.Wait()
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				wg1.Wait()
				return
			}
			log.Println(err)
			continue
		}
		wg1.Add(1)
		go func(conn net.Conn) {
			defer wg1.Done()
			defer conn.Close()
			log.Printf("WRAP+SRTP connection from %s\n", conn.RemoteAddr())

			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error")
				cancel1()
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Println(err)
				cancel1()
				return
			}
			cancel1()
			log.Println("Handshake done")

			pumpBidirectional(ctx, conn, connect, singleClient)
		}(conn)
	}
}

// runSRTPListener is the new SRTP mode (branch add-server-srtp-layer,
// 2026-05-20). Accepts DTLS-SRTP sessions via srtpwrap, which expose
// the same net.Conn interface as a DTLS conn — each Read returns one
// decrypted RTP payload, each Write frames one outgoing payload as an
// RTP+SRTP packet. Bidirectional pump then forwards the payload bytes
// to/from -connect (typically local WireGuard).
func runSRTPListener(ctx context.Context, addr *net.UDPAddr, connect string, singleClient bool) {
	srv, err := srtpwrap.Listen(addr)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		_ = srv.Close()
	})

	log.Printf("Listening (SRTP mode) on %s", srv.Addr())

	wg1 := sync.WaitGroup{}
	for {
		conn, err := srv.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) ||
				errors.Is(err, io.EOF) {
				wg1.Wait()
				return
			}
			log.Printf("SRTP accept: %s", err)
			continue
		}
		wg1.Add(1)
		go func(c net.Conn) {
			defer wg1.Done()
			defer c.Close()
			log.Printf("SRTP session from %s\n", c.RemoteAddr())
			pumpBidirectional(ctx, c, connect, singleClient)
			log.Printf("SRTP session closed: %s\n", c.RemoteAddr())
		}(conn)
	}
}

// pumpBidirectional pumps bytes in both directions between conn and the
// -connect target until either side errors or the context is cancelled.
//
// A connection starts in PER-CONN mode — its own private UDP socket toward
// WireGuard, the historical topology — and is PROMOTED to its client's shared
// group hub when a group hello arrives (M3, see server/group.go). Promotion is
// one-shot: no connection ever leaves a group.
//
// ⚠️ Starting per-conn rather than waiting for a hello is what keeps a client
// that predates this code working unchanged: it never sends one, so it simply
// stays in per-conn mode forever, exactly as it behaves today.
func pumpBidirectional(ctx context.Context, conn net.Conn, connect string, singleClient bool) {
	st := registry.add(conn.RemoteAddr().String())
	defer registry.remove(st)

	var wg sync.WaitGroup
	wg.Add(2)
	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2() // also covers the early returns below, before the pumps start
	context.AfterFunc(ctx2, func() { _ = conn.SetDeadline(time.Now()) })

	// The initial binding. With -single-client, ungrouped connections share one
	// implicit group instead of each dialling its own socket — that is what the
	// flag now means, and it keeps the pre-M3 fast path available to clients
	// that cannot yet send a hello. Everything else starts private.
	var (
		bind   atomic.Pointer[binding]
		joined atomic.Bool
	)
	held := legacyGroupKey
	haveGroup := false
	if singleClient {
		h, err := groups.acquire(ctx, connect, legacyGroupKey)
		if err != nil {
			log.Printf("-single-client: %s", err)
			return
		}
		haveGroup = true
		bind.Store(&binding{hub: h, key: legacyGroupKey, wg: h.wg})
	} else {
		priv, dialErr := net.Dial("udp", connect)
		if dialErr != nil {
			log.Println(dialErr)
			return
		}
		defer func() {
			if err := priv.Close(); err != nil {
				log.Printf("failed to close outgoing connection: %s", err)
			}
		}()
		context.AfterFunc(ctx2, func() { _ = priv.SetDeadline(time.Now()) })
		bind.Store(&binding{wg: priv})
	}
	defer func() {
		if haveGroup {
			groups.release(held)
		}
	}()

	// bindCtx is cancelled to break the outbound goroutine out of whatever it is
	// waiting on so it can pick up a new binding. Only promotion does that.
	bindCtx, bindCancel := context.WithCancel(ctx2)
	defer bindCancel()

	// lastInbound feeds the idle reaper. Updated on EVERY successful read,
	// including probe pings and hellos, because a connection carrying nothing
	// but probes is alive and must not be reaped.
	var lastInbound atomic.Int64
	lastInbound.Store(time.Now().UnixNano())

	// promote moves this connection from its initial binding to its client's
	// group. One-shot: a repeat hello, or one naming a different group, is
	// ignored rather than causing a second migration.
	promote := func(key groupKey) {
		if !joined.CompareAndSwap(false, true) {
			return
		}
		h, err := groups.acquire(ctx, connect, key)
		if err != nil {
			log.Printf("group %s: %s (staying per-conn)", key, err)
			return
		}
		old := bind.Load()
		bind.Store(&binding{hub: h, key: key, wg: h.wg})
		if haveGroup {
			groups.release(held)
		}
		held, haveGroup = key, true
		// ⚠️ The private socket is deliberately NOT closed here. The inbound
		// goroutine may already have loaded the old binding and be about to
		// write to it; closing under it would kill a healthy connection. It is
		// idle from now on and closes with the function. The cost is a short
		// window in which WireGuard's endpoint may still point at it and its
		// packets are lost — one packet-interval, until the client's next
		// uplink through the shared socket re-points the peer.
		if old.hub == nil {
			log.Printf("conn %d joined group %s", st.id, key)
		} else {
			log.Printf("conn %d moved from the -single-client group to %s", st.id, key)
		}
		bindCancel() // break the outbound goroutine out of the old binding
	}

	// inbound: conn → connect target (with probe-echo gate)
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			n, err1 := conn.Read(buf)
			if err1 != nil {
				log.Printf("inbound read failed: %s", err1)
				return
			}
			// Any successful read is proof of life for the reaper, including
			// probes and hellos — a connection carrying nothing else is alive.
			lastInbound.Store(time.Now().UnixNano())

			// Group hello (M3): consume it, never forward it. Checked before
			// the probe gate only because both are cheap constant-time tests on
			// the same leading 0xff.
			if key, ok := isGroupHello(buf[:n]); ok {
				promote(key)
				continue
			}
			// Probe-echo: the iOS client sends a 12-byte sentinel
			// (0xff 'P' 'N' 'G' + 8-byte BE seq) on each conn at
			// probeInterval to detect zombie conns. Echo it back
			// verbatim INSTEAD of forwarding to the local WG, which
			// would drop it as an invalid WG message type and provide
			// no liveness signal back to the client. Without this
			// echo, the client's serverProbeable flag never flips
			// true and its zombie-detection path stays dormant —
			// fully backward-compatible but missing the post-wake
			// fast-kill machinery. Mirrors the probe-echo cherry-
			// picked from upstream PR #168 into add-server-wrap-layer
			// (commit ccea0d4) — same wire format so both branches
			// echo the same packets, and the same client-side
			// recognizer (isProbePacket) handles either response.
			if n >= 4 && buf[0] == 0xff && buf[1] == 'P' && buf[2] == 'N' && buf[3] == 'G' {
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err1 = conn.Write(buf[:n]); err1 != nil {
					log.Printf("probe-echo write failed: %s", err1)
					return
				}
				continue
			}
			// Measured HERE, at the merge point, because this is where the
			// client's N connections become one stream — the displacement a
			// packet has at this instant is exactly what the fan-out did to it,
			// and what the inner TCP downstream will read as loss.
			uplinkReorder.observe(buf[:n], time.Now())

			b := bind.Load()
			// A shared socket carries every connection's uplink, so a write
			// deadline set here would apply to all of them — skip it in group
			// mode. UDP writes to a connected socket do not block anyway.
			if b.hub == nil {
				_ = b.wg.SetWriteDeadline(time.Now().Add(30 * time.Minute))
			}
			// M5: when the group has a resequencer, WireGuard is reached only
			// through it, so the order it computes is the order WireGuard sees.
			// Ungrouped connections do not merge with anything and go direct.
			if b.hub != nil && b.hub.reseq != nil {
				err1 = b.hub.reseq.write(buf[:n])
			} else {
				_, err1 = b.wg.Write(buf[:n])
			}
			if err1 != nil {
				log.Printf("inbound write failed: %s", err1)
				return
			}
			st.up.Add(int64(n))
		}
	}()

	// outbound: WireGuard → conn. Runs the current binding until it dies; if
	// that was a promotion, picks up the new one and runs that instead. At most
	// two iterations, because promotion is one-shot.
	go func() {
		defer wg.Done()
		defer cancel2()
		serveCtx := bindCtx
		for {
			b := bind.Load()
			if b.hub != nil {
				// Steal packets from the group's return queue instead of owning
				// a private socket. Whoever is free takes the next one.
				b.hub.serveConn(serveCtx, conn, st)
			} else {
				pumpPrivateDownlink(serveCtx, conn, b.wg, st)
			}
			if bind.Load() == b {
				return // nothing was swapped under us: a genuine exit
			}
			serveCtx = ctx2 // promotion is one-shot; no further rebinding
		}
	}()

	// Idle reaper (M3). Only meaningful in group mode: a per-conn connection
	// that goes silent hurts nobody, but one inside a group keeps stealing from
	// the shared queue and dropping what it steals.
	go func() {
		t := time.NewTicker(groupReapEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-t.C:
				if bind.Load().hub == nil {
					continue
				}
				idle := time.Since(time.Unix(0, lastInbound.Load()))
				if idle > groupIdleTimeout {
					log.Printf("conn %d: no inbound for %s, reaping — a silent "+
						"connection in a group still steals downlink",
						st.id, idle.Round(time.Second))
					cancel2()
					return
				}
			}
		}
	}()
	wg.Wait()
	log.Printf("Connection closed: %s\n", conn.RemoteAddr())
}

// pumpPrivateDownlink is the historical per-connection return path: read this
// connection's own socket toward WireGuard and write what comes back. Returns
// when the socket or the connection dies, or when ctx is cancelled — which is
// also how a promotion to a group breaks it out.
func pumpPrivateDownlink(ctx context.Context, conn, priv net.Conn, st *connStat) {
	stop := context.AfterFunc(ctx, func() { _ = priv.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, 1600)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = priv.SetReadDeadline(time.Now().Add(30 * time.Minute))
		n, err := priv.Read(buf)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("outbound read failed: %s", err)
			}
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
		if _, err = conn.Write(buf[:n]); err != nil {
			log.Printf("outbound write failed: %s", err)
			return
		}
		st.down.Add(int64(n))
		st.downPkts.Add(1)
	}
}
