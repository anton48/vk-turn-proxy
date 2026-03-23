package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// Config holds proxy configuration.
type Config struct {
	PeerAddr   string // vk-turn-proxy server address (host:port)
	TurnServer string // override TURN server host (optional)
	TurnPort   string // override TURN port (optional)
	VKLink     string // VK call invite link or link ID
	UseDTLS    bool   // true = DTLS obfuscation (default mode)
	UseUDP     bool   // true = UDP to TURN, false = TCP
	NumConns   int    // number of concurrent connections (default 1)
}

// Stats holds live tunnel statistics.
type Stats struct {
	TxBytes           int64   `json:"tx_bytes"`
	RxBytes           int64   `json:"rx_bytes"`
	ActiveConns       int32   `json:"active_conns"`
	TotalConns        int32   `json:"total_conns"`
	TurnRTTms         float64 `json:"turn_rtt_ms"`         // last TURN Allocate RTT
	DTLSHandshakeMs   float64 `json:"dtls_handshake_ms"`   // last DTLS handshake time
	LastHandshakeSec  int64   `json:"last_handshake_sec"`  // seconds since last WG handshake
	Reconnects        int64   `json:"reconnects"`          // total TURN reconnects
}

// Proxy manages the DTLS+TURN tunnel to the peer server.
type Proxy struct {
	config Config
	ctx    context.Context    // global lifetime (wgTurnOn → wgTurnOff)
	cancel context.CancelFunc

	peer   *net.UDPAddr
	linkID string

	// For packet I/O from the WireGuard side
	sendCh chan []byte
	recvCh chan []byte

	wg sync.WaitGroup

	started atomic.Bool

	// Active session context (cancelled on Pause, recreated on Resume)
	sessMu     sync.Mutex
	sessCtx    context.Context
	sessCancel context.CancelFunc

	// TURN server IP discovered after connecting to VK
	turnServerIP atomic.Value // stores string

	// Stats
	txBytes      atomic.Int64
	rxBytes      atomic.Int64
	activeConns  atomic.Int32
	totalConns   atomic.Int32
	turnRTTns    atomic.Int64  // nanoseconds
	dtlsHSns    atomic.Int64  // nanoseconds
	reconnects   atomic.Int64
}

// NewProxy creates a new proxy instance.
func NewProxy(cfg Config) *Proxy {
	if cfg.NumConns <= 0 {
		cfg.NumConns = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	sessCtx, sessCancel := context.WithCancel(ctx)
	return &Proxy{
		config:     cfg,
		ctx:        ctx,
		cancel:     cancel,
		sendCh:     make(chan []byte, 256),
		recvCh:     make(chan []byte, 256),
		sessCtx:    sessCtx,
		sessCancel: sessCancel,
	}
}

// Start establishes the DTLS+TURN connection chain.
// It blocks until the first connection is established or an error occurs.
func (p *Proxy) Start() error {
	if p.started.Swap(true) {
		return fmt.Errorf("proxy already started")
	}

	// Parse VK link ID
	linkID := p.config.VKLink
	if strings.Contains(linkID, "join/") {
		parts := strings.Split(linkID, "join/")
		linkID = parts[len(parts)-1]
	}
	if idx := strings.IndexAny(linkID, "/?#"); idx != -1 {
		linkID = linkID[:idx]
	}
	p.linkID = linkID

	// Resolve peer address
	peer, err := net.ResolveUDPAddr("udp", p.config.PeerAddr)
	if err != nil {
		return fmt.Errorf("resolve peer: %w", err)
	}
	p.peer = peer

	return p.startConnections()
}

// startConnections launches all connection goroutines using the current session context.
func (p *Proxy) startConnections() error {
	p.sessMu.Lock()
	sessCtx := p.sessCtx
	p.sessMu.Unlock()

	readyCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		err := p.runConnection(sessCtx, p.linkID, readyCh)
		if err != nil {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	select {
	case <-readyCh:
	case err := <-errCh:
		return fmt.Errorf("first connection failed: %w", err)
	case <-p.ctx.Done():
		return p.ctx.Err()
	}

	for i := 1; i < p.config.NumConns; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.runConnection(sessCtx, p.linkID, nil)
		}()
	}

	return nil
}

// Pause gracefully stops all connections (for sleep).
func (p *Proxy) Pause() {
	p.sessMu.Lock()
	p.sessCancel()
	p.sessMu.Unlock()
	log.Printf("proxy: Pause — all connections cancelled")
}

// Resume restarts all connections (for wake).
func (p *Proxy) Resume() {
	p.sessMu.Lock()
	p.sessCtx, p.sessCancel = context.WithCancel(p.ctx)
	p.sessMu.Unlock()
	log.Printf("proxy: Resume — starting fresh connections")
	go p.startConnections()
}

// SendPacket sends a WireGuard packet through the tunnel.
func (p *Proxy) SendPacket(data []byte) error {
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case p.sendCh <- buf:
		p.txBytes.Add(int64(len(data)))
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// ReceivePacket receives a packet from the tunnel.
// Blocks until a packet arrives or context is cancelled.
func (p *Proxy) ReceivePacket(buf []byte) (int, error) {
	select {
	case pkt := <-p.recvCh:
		n := copy(buf, pkt)
		p.rxBytes.Add(int64(n))
		return n, nil
	case <-p.ctx.Done():
		return 0, p.ctx.Err()
	}
}

// GetStats returns current tunnel statistics.
func (p *Proxy) GetStats() Stats {
	return Stats{
		TxBytes:          p.txBytes.Load(),
		RxBytes:          p.rxBytes.Load(),
		ActiveConns:      p.activeConns.Load(),
		TotalConns:       p.totalConns.Load(),
		TurnRTTms:        float64(p.turnRTTns.Load()) / 1e6,
		DTLSHandshakeMs:  float64(p.dtlsHSns.Load()) / 1e6,
		Reconnects:       p.reconnects.Load(),
	}
}

// TURNServerIP returns the TURN server IP discovered after connecting.
// Returns empty string if not yet connected.
func (p *Proxy) TURNServerIP() string {
	if v := p.turnServerIP.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Stop tears down all connections.
func (p *Proxy) Stop() {
	p.cancel()
	p.wg.Wait()
}

// runConnection runs a single connection slot with reconnection.
// Reconnects on failure until sessCtx is cancelled (Pause/Resume) or global ctx is done (Stop).
// After 3 consecutive short-lived failures, goes dormant until Resume() restarts via sessCtx.
func (p *Proxy) runConnection(sessCtx context.Context, linkID string, readyCh chan<- struct{}) error {
	signaled := false
	shortFailures := 0

	for {
		select {
		case <-sessCtx.Done():
			return sessCtx.Err()
		case <-p.ctx.Done():
			return p.ctx.Err()
		default:
		}

		start := time.Now()
		var err error
		if p.config.UseDTLS {
			err = p.runDTLSSession(sessCtx, linkID, readyCh, &signaled)
		} else {
			err = p.runDirectSession(sessCtx, linkID, readyCh, &signaled)
		}
		if err != nil {
			duration := time.Since(start)
			log.Printf("proxy: session ended after %s: %s", duration.Round(time.Second), err)
			if !signaled && readyCh != nil {
				return err
			}

			if duration > 5*time.Minute {
				shortFailures = 0 // session was healthy
			} else {
				shortFailures++
			}

			// After 3 consecutive short-lived failures, go dormant.
			// Device is likely sleeping. Wait for Resume() (which cancels sessCtx).
			if shortFailures >= 3 {
				log.Printf("proxy: %d consecutive short failures, going dormant until Resume()", shortFailures)
				select {
				case <-sessCtx.Done():
					return sessCtx.Err()
				case <-p.ctx.Done():
					return p.ctx.Err()
				}
			}

			// Brief delay before reconnect
			select {
			case <-time.After(2 * time.Second):
			case <-sessCtx.Done():
				return sessCtx.Err()
			case <-p.ctx.Done():
				return p.ctx.Err()
			}
		}
	}
}

// resolveTURNAddr fetches VK credentials and resolves the TURN server address.
func (p *Proxy) resolveTURNAddr(linkID string) (string, *TURNCreds, error) {
	creds, err := GetVKCreds(linkID)
	if err != nil {
		return "", nil, fmt.Errorf("get VK creds: %w", err)
	}
	turnHost, turnPort, err := net.SplitHostPort(creds.Address)
	if err != nil {
		return "", nil, fmt.Errorf("parse TURN address: %w", err)
	}
	if p.config.TurnServer != "" {
		turnHost = p.config.TurnServer
	}
	if p.config.TurnPort != "" {
		turnPort = p.config.TurnPort
	}
	p.turnServerIP.Store(turnHost)
	return net.JoinHostPort(turnHost, turnPort), creds, nil
}

// runDTLSSession runs a long-lived DTLS session.
// DTLS stays alive while TURN reconnects underneath with fresh creds only on failure.
// Only returns when DTLS itself fails (then the caller restarts everything).
func (p *Proxy) runDTLSSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool) error {
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	// Create AsyncPacketPipe: conn1 = DTLS transport, conn2 = TURN transport.
	// The same conn2 is reused across TURN reconnections (matching the original client).
	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	// Get initial credentials and start first TURN relay
	turnAddr, creds, err := p.resolveTURNAddr(linkID)
	if err != nil {
		return err
	}

	// Start TURN relay FIRST — DTLS handshake goes through it.
	// TURN runs until it fails naturally (no forced lifetime).
	// The pion/turn client handles allocation refresh automatically.
	turnDone := make(chan error, 1)
	go func() {
		turnDone <- p.runTURN(connCtx, turnAddr, creds, conn2)
	}()

	// DTLS handshake — packets go through conn1 → conn2 → TURN relay → peer
	dtlsStart := time.Now()
	dtlsConn, err := dialDTLS(connCtx, conn1, p.peer)
	if err != nil {
		connCancel()
		select {
		case turnErr := <-turnDone:
			if turnErr != nil {
				return fmt.Errorf("DTLS failed: %w (TURN error: %v)", err, turnErr)
			}
		default:
		}
		return fmt.Errorf("DTLS: %w", err)
	}
	defer dtlsConn.Close()

	// Close DTLS when context is cancelled to unblock Read() immediately.
	context.AfterFunc(connCtx, func() {
		dtlsConn.Close()
	})

	// Record DTLS handshake time
	p.dtlsHSns.Store(int64(time.Since(dtlsStart)))
	p.activeConns.Add(1)
	p.totalConns.Add(1)
	defer p.activeConns.Add(-1)

	// Signal ready
	if readyCh != nil && !*signaled {
		*signaled = true
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}

	log.Printf("proxy: DTLS+TURN session established")

	// TURN reconnection loop in background.
	// Only reconnects when TURN actually fails (not proactively).
	// The same conn2 is reused — DTLS doesn't see the reconnection.
	go func() {
		defer connCancel() // if TURN loop gives up, kill DTLS too
		for {
			// Wait for current TURN to finish (it runs until failure)
			select {
			case <-turnDone:
			case <-connCtx.Done():
				return
			}

			if connCtx.Err() != nil {
				return
			}

			p.reconnects.Add(1)
		log.Printf("proxy: TURN session ended, reconnecting...")

			// Brief pause before reconnecting
			select {
			case <-time.After(500 * time.Millisecond):
			case <-connCtx.Done():
				return
			}

			// Get fresh VK credentials and reconnect TURN
			retries := 0
			for retries < 5 {
				if connCtx.Err() != nil {
					return
				}
				newAddr, newCreds, err := p.resolveTURNAddr(linkID)
				if err != nil {
					retries++
					log.Printf("proxy: TURN creds fetch failed (attempt %d/5): %s", retries, err)
					select {
					case <-time.After(time.Duration(retries) * time.Second):
					case <-connCtx.Done():
						return
					}
					continue
				}

				log.Printf("proxy: starting new TURN session (attempt %d)", retries+1)
				turnDone = make(chan error, 1)
				go func() {
					turnDone <- p.runTURN(connCtx, newAddr, newCreds, conn2)
				}()
				break
			}
			if retries >= 5 {
				log.Printf("proxy: TURN reconnection failed after 5 attempts, giving up")
				return // session dies → runConnection will wait 5 min or ForceReconnect
			}
		}
	}()

	// Bidirectional forwarding: sendCh ↔ dtlsConn (long-lived)
	var wg sync.WaitGroup
	wg.Add(2)

	// Send: sendCh → dtlsConn
	go func() {
		defer wg.Done()
		defer connCancel()
		for {
			select {
			case <-connCtx.Done():
				return
			case pkt := <-p.sendCh:
				dtlsConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := dtlsConn.Write(pkt); err != nil {
					return
				}
			}
		}
	}()

	// Receive: dtlsConn → recvCh
	go func() {
		defer wg.Done()
		defer connCancel()
		buf := make([]byte, 1600)
		for {
			dtlsConn.SetReadDeadline(time.Now().Add(4 * time.Hour))
			n, err := dtlsConn.Read(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case p.recvCh <- pkt:
			case <-connCtx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// runDirectSession runs a direct TURN session (no DTLS).
// TURN reconnects with fresh creds only on failure.
func (p *Proxy) runDirectSession(sessCtx context.Context, linkID string, readyCh chan<- struct{}, signaled *bool) error {
	connCtx, connCancel := context.WithCancel(sessCtx)
	defer connCancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	defer conn1.Close()
	defer conn2.Close()

	context.AfterFunc(connCtx, func() {
		conn1.Close()
	})

	turnAddr, creds, err := p.resolveTURNAddr(linkID)
	if err != nil {
		return err
	}

	turnDone := make(chan error, 1)
	go func() {
		turnDone <- p.runTURN(connCtx, turnAddr, creds, conn2)
	}()

	if readyCh != nil && !*signaled {
		*signaled = true
		select {
		case readyCh <- struct{}{}:
		default:
		}
	}

	// TURN reconnection loop (same as DTLS version but without DTLS)
	go func() {
		defer connCancel()
		for {
			select {
			case <-turnDone:
			case <-connCtx.Done():
				return
			}
			if connCtx.Err() != nil {
				return
			}
			log.Printf("proxy: direct TURN ended, reconnecting...")
			select {
			case <-time.After(500 * time.Millisecond):
			case <-connCtx.Done():
				return
			}
			retries := 0
			for retries < 5 {
				if connCtx.Err() != nil {
					return
				}
				newAddr, newCreds, err := p.resolveTURNAddr(linkID)
				if err != nil {
					retries++
					select {
					case <-time.After(time.Duration(retries) * time.Second):
					case <-connCtx.Done():
						return
					}
					continue
				}
				turnDone = make(chan error, 1)
				go func() {
					turnDone <- p.runTURN(connCtx, newAddr, newCreds, conn2)
				}()
				break
			}
			if retries >= 5 {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer connCancel()
		for {
			select {
			case <-connCtx.Done():
				return
			case pkt := <-p.sendCh:
				conn1.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn1.WriteTo(pkt, p.peer); err != nil {
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer connCancel()
		buf := make([]byte, 1600)
		for {
			conn1.SetReadDeadline(time.Now().Add(4 * time.Hour))
			n, _, err := conn1.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case p.recvCh <- pkt:
			case <-connCtx.Done():
				return
			}
		}
	}()

	wg.Wait()
	return nil
}

// runTURN establishes a TURN relay and forwards packets between conn2 and the relay.
// Runs until the relay fails or ctx is cancelled. No forced lifetime —
// the pion/turn client handles allocation refresh automatically.
// conn2's deadline is reset before returning so it can be reused.
func (p *Proxy) runTURN(ctx context.Context, turnAddr string, creds *TURNCreds, conn2 net.PacketConn) error {
	turnUDPAddr, err := net.ResolveUDPAddr("udp", turnAddr)
	if err != nil {
		return fmt.Errorf("resolve TURN: %w", err)
	}

	// Connect to TURN server
	var turnConn net.PacketConn
	if p.config.UseUDP {
		udpConn, err := net.DialUDP("udp", nil, turnUDPAddr)
		if err != nil {
			return fmt.Errorf("dial TURN UDP: %w", err)
		}
		defer udpConn.Close()
		turnConn = &connectedUDPConn{udpConn}
	} else {
		tcpCtx, tcpCancel := context.WithTimeout(ctx, 5*time.Second)
		defer tcpCancel()
		var d net.Dialer
		tcpConn, err := d.DialContext(tcpCtx, "tcp", turnAddr)
		if err != nil {
			return fmt.Errorf("dial TURN TCP: %w", err)
		}
		defer tcpConn.Close()
		turnConn = turn.NewSTUNConn(tcpConn)
	}

	// Determine address family
	var addrFamily turn.RequestedAddressFamily
	if p.peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr:         turnAddr,
		TURNServerAddr:         turnAddr,
		Conn:                   turnConn,
		Username:               creds.Username,
		Password:               creds.Password,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("TURN client: %w", err)
	}
	defer client.Close()

	if err = client.Listen(); err != nil {
		return fmt.Errorf("TURN listen: %w", err)
	}

	allocStart := time.Now()
	relayConn, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("TURN allocate: %w", err)
	}
	defer relayConn.Close()
	p.turnRTTns.Store(int64(time.Since(allocStart)))

	log.Printf("proxy: TURN relay allocated: %s (RTT %dms)", relayConn.LocalAddr(), time.Since(allocStart).Milliseconds())

	// Bidirectional forwarding: conn2 ↔ relayConn
	var wg sync.WaitGroup
	wg.Add(2)
	turnCtx, turnCancel := context.WithCancel(ctx)
	defer turnCancel()
	context.AfterFunc(turnCtx, func() {
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})

	var peerAddr atomic.Value

	// conn2 → relay
	go func() {
		defer wg.Done()
		defer turnCancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnCtx.Done():
				return
			default:
			}
			n, addr, err := conn2.ReadFrom(buf)
			if err != nil {
				return
			}
			peerAddr.Store(addr)
			if _, err = relayConn.WriteTo(buf[:n], p.peer); err != nil {
				return
			}
		}
	}()

	// relay → conn2
	go func() {
		defer wg.Done()
		defer turnCancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnCtx.Done():
				return
			default:
			}
			n, _, err := relayConn.ReadFrom(buf)
			if err != nil {
				return
			}
			addr, ok := peerAddr.Load().(net.Addr)
			if !ok {
				return
			}
			if _, err = conn2.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	// Reset conn2 deadline so it can be reused by the next TURN session.
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
	return nil
}

// dialDTLS establishes a DTLS connection using the given PacketConn as transport.
func dialDTLS(ctx context.Context, transport net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	dtlsConn, err := dtls.Client(transport, peer, config)
	if err != nil {
		return nil, err
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, 30*time.Second)
	defer hsCancel()
	if err := dtlsConn.HandshakeContext(hsCtx); err != nil {
		dtlsConn.Close()
		return nil, err
	}
	return dtlsConn, nil
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}
