package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
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
			"listener — pick one mode per server instance.")
	logFile := flag.String("logfile", "",
		"if set, append log output to this file instead of stdout. The "+
			"file is opened in append mode (O_APPEND|O_CREATE) so logs from "+
			"multiple restarts accumulate. Both the standard log.* calls and "+
			"the startup banner go through the same writer.")
	flag.Parse()

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open logfile %q: %v", *logFile, err)
		}
		defer f.Close()
		log.SetOutput(f)
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

	if *useSrtp {
		runSRTPListener(ctx, addr, *connect)
		return
	}
	runDTLSListener(ctx, addr, *connect)
}

// runDTLSListener is the legacy listener mode — accepts DTLS sessions
// directly and pumps decrypted bytes to/from the -connect target. This
// is what the unmodified pre-2026-05-20 server was always doing.
func runDTLSListener(ctx context.Context, addr *net.UDPAddr, connect string) {
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

			pumpBidirectional(ctx, conn, connect)
		}(conn)
	}
}

// runSRTPListener is the new SRTP mode (branch add-server-srtp-layer,
// 2026-05-20). Accepts DTLS-SRTP sessions via srtpwrap, which expose
// the same net.Conn interface as a DTLS conn — each Read returns one
// decrypted RTP payload, each Write frames one outgoing payload as an
// RTP+SRTP packet. Bidirectional pump then forwards the payload bytes
// to/from -connect (typically local WireGuard).
func runSRTPListener(ctx context.Context, addr *net.UDPAddr, connect string) {
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
			pumpBidirectional(ctx, c, connect)
			log.Printf("SRTP session closed: %s\n", c.RemoteAddr())
		}(conn)
	}
}

// pumpBidirectional dials the -connect target via UDP and pumps bytes
// in both directions between conn and that target until either side
// returns an error or the context is cancelled.
func pumpBidirectional(ctx context.Context, conn net.Conn, connect string) {
	serverConn, err := net.Dial("udp", connect)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err = serverConn.Close(); err != nil {
			log.Printf("failed to close outgoing connection: %s", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	ctx2, cancel2 := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		_ = conn.SetDeadline(time.Now())
		_ = serverConn.SetDeadline(time.Now())
	})

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
			_ = serverConn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
			if _, err1 = serverConn.Write(buf[:n]); err1 != nil {
				log.Printf("inbound write failed: %s", err1)
				return
			}
		}
	}()

	// outbound: connect target → conn
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
			_ = serverConn.SetReadDeadline(time.Now().Add(30 * time.Minute))
			n, err1 := serverConn.Read(buf)
			if err1 != nil {
				log.Printf("outbound read failed: %s", err1)
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Minute))
			if _, err1 = conn.Write(buf[:n]); err1 != nil {
				log.Printf("outbound write failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
	log.Printf("Connection closed: %s\n", conn.RemoteAddr())
}
