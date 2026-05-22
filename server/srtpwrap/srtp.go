// Package srtpwrap provides a thin SRTP-over-DTLS adapter used by the
// server's -srtp listener mode (added in branch add-server-srtp-layer
// 2026-05-20) to accept traffic from clients running the SRTP-wrap
// transport. The wire framing makes our tunnel payload look like
// legitimate WebRTC media to VK's TURN-relay content classifier,
// completely bypassing VK's per-allocation shape policy. It exposes
// two entry points:
//
//   - Client(ctx, underlay, remote) -> net.Conn that performs the DTLS
//     handshake on top of an existing PacketConn (e.g. a TURN-relayed
//     conn returned by pion/turn) and returns a wrapper that frames
//     every Write call as one RTP/SRTP packet (PayloadType 100 — used
//     to imitate VP8 WebRTC video) and decrypts incoming SRTP packets
//     on Read.
//
//   - Listen(ctx, addr) -> *Server, then srv.Accept() to yield one
//     net.Conn per new source address. Server demultiplexes incoming
//     UDP packets by first-byte range (DTLS 20..63, RTP 128..191) so
//     that one listening socket can handle many simultaneous clients.
//
// Independent implementation written from the relevant RFCs (RFC 3550
// for RTP framing, RFC 3711 for SRTP, RFC 5764 for DTLS-SRTP key
// derivation) and the public APIs of pion/dtls + pion/rtp + pion/srtp.
// No code copied from any GPL-licensed third party.
package srtpwrap

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

const (
	// PayloadType for the synthetic RTP wrapper. 100 is the dynamic-range
	// value commonly assigned to VP8 in WebRTC SDP offers, so receivers
	// that classify by payload type see "looks like VP8 video".
	PayloadType uint8 = 100

	// MTU caps DTLS record + RTP+SRTP payload at a size that still fits
	// inside a single IP/UDP datagram after TURN ChannelData wrapping
	// (4 bytes) and IPv4/UDP headers (~28 bytes).
	MTU = 1200

	// HandshakeTimeout bounds a single DTLS handshake attempt.
	HandshakeTimeout = 10 * time.Second
)

// IsDTLS reports whether b looks like the first byte of a DTLS record
// (ContentType range 20..63 per RFC 9147 + RFC 5764 demux table).
func IsDTLS(b byte) bool { return b >= 20 && b <= 63 }

// IsRTP reports whether b looks like the first byte of an RTP/SRTP
// packet (version-2 in top 2 bits → 128..191).
func IsRTP(b byte) bool { return b >= 128 && b <= 191 }

// ─── Client ───────────────────────────────────────────────────────────────

// Client performs a DTLS-SRTP handshake on top of an existing
// PacketConn talking to remote, and returns a net.Conn whose Read/Write
// methods carry user payload framed as RTP and encrypted as SRTP.
//
// underlay can be any net.PacketConn — including a TURN-relayed conn
// returned by pion/turn's client.Allocate().
func Client(ctx context.Context, underlay net.PacketConn, remote net.Addr) (net.Conn, error) {
	if underlay == nil {
		return nil, errors.New("srtpwrap: underlay is nil")
	}
	if remote == nil {
		return nil, errors.New("srtpwrap: remote is nil")
	}

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("srtpwrap: cert gen: %w", err)
	}

	dtlsCh := make(chan []byte, 64)
	rtpCh := make(chan []byte, 4096)
	// See pkg/proxy/srtpwrap/srtp.go for the long explanation. tl;dr:
	// production callers cancel `ctx` immediately after Client() returns
	// (since they pass a handshake-timeout ctx), which would silently
	// kill the demux goroutine and drop every post-handshake RTP packet.
	// Demux lifetime is bound to wrappedConn.Close (via stopDemux below).
	demuxCtx, demuxCancel := context.WithCancel(context.Background())
	go runDemuxFromPacketConn(demuxCtx, underlay, dtlsCh, rtpCh)

	adapter := &packetConnAdapter{
		raw:    underlay,
		ch:     dtlsCh,
		addr:   remote,
		closed: make(chan struct{}),
	}

	// pion/dtls v3.x Client()/Server() only set up the Conn — the
	// handshake itself runs lazily on first Read/Write OR via an
	// explicit HandshakeContext call. Call it explicitly so we
	// control timeout + so ConnectionState is populated when we
	// extract SRTP keys below.
	dconn, err := dtls.Client(adapter, remote, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
		InsecureSkipVerify: true,
	})
	if err != nil {
		_ = adapter.Close()
		demuxCancel()
		return nil, fmt.Errorf("srtpwrap: dtls client init: %w", err)
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, HandshakeTimeout)
	hsErr := dconn.HandshakeContext(hsCtx)
	hsCancel()
	if hsErr != nil {
		_ = dconn.Close()
		_ = adapter.Close()
		demuxCancel()
		return nil, fmt.Errorf("srtpwrap: dtls client handshake: %w", hsErr)
	}

	wrap, err := newWrappedConn(underlay, remote, dconn, rtpCh, true /*isClient*/, demuxCancel)
	if err != nil {
		_ = dconn.Close()
		_ = adapter.Close()
		demuxCancel()
		return nil, fmt.Errorf("srtpwrap: post-handshake setup: %w", err)
	}
	return wrap, nil
}

// ─── Server ───────────────────────────────────────────────────────────────

// Server listens on a UDP socket and yields one wrapped conn per new
// source address.
type Server struct {
	raw    *net.UDPConn
	out    chan net.Conn
	errCh  chan error
	closed chan struct{}

	cert tls.Certificate

	mu       sync.Mutex
	sessions map[string]*serverSession
}

type serverSession struct {
	dtlsCh chan []byte
	rtpCh  chan []byte
}

// Listen opens the UDP socket and starts the demultiplexer goroutine.
func Listen(addr *net.UDPAddr) (*Server, error) {
	raw, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("srtpwrap: listen %s: %w", addr, err)
	}
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("srtpwrap: cert gen: %w", err)
	}
	s := &Server{
		raw:      raw,
		out:      make(chan net.Conn, 16),
		errCh:    make(chan error, 1),
		closed:   make(chan struct{}),
		cert:     cert,
		sessions: make(map[string]*serverSession),
	}
	go s.demux()
	return s, nil
}

// Addr returns the local UDP address.
func (s *Server) Addr() net.Addr { return s.raw.LocalAddr() }

// Accept blocks until a new session has finished its DTLS handshake.
func (s *Server) Accept(ctx context.Context) (net.Conn, error) {
	select {
	case c, ok := <-s.out:
		if !ok {
			return nil, io.EOF
		}
		return c, nil
	case err := <-s.errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, net.ErrClosed
	}
}

// Close stops the demux loop and closes the UDP socket.
func (s *Server) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	return s.raw.Close()
}

func (s *Server) demux() {
	buf := make([]byte, 2048)
	for {
		n, src, err := s.raw.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				log.Printf("srtpwrap: demux read error: %v", err)
				continue
			}
		}
		if n == 0 {
			continue
		}
		key := src.String()
		s.mu.Lock()
		sess, ok := s.sessions[key]
		if !ok {
			sess = &serverSession{
				dtlsCh: make(chan []byte, 64),
				rtpCh:  make(chan []byte, 4096),
			}
			s.sessions[key] = sess
			s.mu.Unlock()
			go s.handshakeAndPublish(src, sess)
		} else {
			s.mu.Unlock()
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		switch {
		case IsDTLS(pkt[0]):
			select {
			case sess.dtlsCh <- pkt:
			default:
				log.Printf("srtpwrap: dropped DTLS packet from %s (dtlsCh full)", src)
			}
		case IsRTP(pkt[0]):
			select {
			case sess.rtpCh <- pkt:
			default:
				log.Printf("srtpwrap: dropped RTP packet from %s (rtpCh full)", src)
			}
		}
	}
}

func (s *Server) handshakeAndPublish(src net.Addr, sess *serverSession) {
	t0 := time.Now()
	adapter := &packetConnAdapter{
		raw:    s.raw,
		ch:     sess.dtlsCh,
		addr:   src,
		closed: make(chan struct{}),
	}
	dconn, err := dtls.Server(adapter, src, &dtls.Config{
		Certificates:         []tls.Certificate{s.cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
	})
	if err != nil {
		log.Printf("srtpwrap: dtls.Server() failed for %s: %v", src, err)
		_ = adapter.Close()
		s.mu.Lock()
		delete(s.sessions, src.String())
		s.mu.Unlock()
		return
	}
	// Explicit handshake — pion/dtls Server() returns before
	// handshake runs (handshake is lazy on first Read/Write).
	hsCtx, hsCancel := context.WithTimeout(context.Background(), HandshakeTimeout)
	hsErr := dconn.HandshakeContext(hsCtx)
	hsCancel()
	if hsErr != nil {
		log.Printf("srtpwrap: handshake failed for %s after %s: %v", src, time.Since(t0).Round(time.Millisecond), hsErr)
		_ = dconn.Close()
		_ = adapter.Close()
		s.mu.Lock()
		delete(s.sessions, src.String())
		s.mu.Unlock()
		return
	}
	wrap, err := newWrappedConn(s.raw, src, dconn, sess.rtpCh, false /*isClient*/, nil)
	if err != nil {
		log.Printf("srtpwrap: newWrappedConn failed for %s: %v", src, err)
		_ = dconn.Close()
		_ = adapter.Close()
		s.mu.Lock()
		delete(s.sessions, src.String())
		s.mu.Unlock()
		return
	}
	wrap.onClose = func() {
		s.mu.Lock()
		delete(s.sessions, src.String())
		s.mu.Unlock()
	}
	log.Printf("srtpwrap: session %s ready (handshake %s)", src, time.Since(t0).Round(time.Millisecond))
	select {
	case s.out <- wrap:
	case <-s.closed:
		_ = wrap.Close()
	}
}

// ─── packetConnAdapter ────────────────────────────────────────────────────

// packetConnAdapter exposes a channel of demuxed DTLS bytes as a
// net.PacketConn so pion/dtls can read handshake records from it
// while RTP/SRTP traffic on the same UDP socket is routed elsewhere.
// Writes pass through unchanged to the underlying raw conn.
type packetConnAdapter struct {
	raw       net.PacketConn
	ch        chan []byte
	addr      net.Addr
	closed    chan struct{}
	closeOnce sync.Once

	mu    sync.Mutex
	dlExp time.Time
	dlCh  chan struct{}
}

func (a *packetConnAdapter) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		dl := a.deadlineCh()
		select {
		case pkt, ok := <-a.ch:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return copy(b, pkt), a.addr, nil
		case <-a.closed:
			return 0, nil, net.ErrClosed
		case <-dl:
			if a.deadlineExpired() {
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
}

func (a *packetConnAdapter) WriteTo(b []byte, _ net.Addr) (int, error) {
	return a.raw.WriteTo(b, a.addr)
}

func (a *packetConnAdapter) LocalAddr() net.Addr { return a.raw.LocalAddr() }

func (a *packetConnAdapter) SetDeadline(t time.Time) error {
	a.setDl(t)
	return nil
}

func (a *packetConnAdapter) SetReadDeadline(t time.Time) error {
	a.setDl(t)
	return nil
}

func (a *packetConnAdapter) SetWriteDeadline(t time.Time) error { return nil }

func (a *packetConnAdapter) Close() error {
	a.closeOnce.Do(func() { close(a.closed) })
	return nil
}

func (a *packetConnAdapter) deadlineCh() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dlCh == nil {
		a.dlCh = make(chan struct{})
	}
	return a.dlCh
}

func (a *packetConnAdapter) deadlineExpired() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.dlExp.IsZero() && !time.Now().Before(a.dlExp)
}

func (a *packetConnAdapter) setDl(t time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dlCh != nil {
		select {
		case <-a.dlCh:
		default:
			close(a.dlCh)
		}
	}
	a.dlCh = make(chan struct{})
	a.dlExp = t
	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			close(a.dlCh)
			return
		}
		ch := a.dlCh
		// CAS-style timer callback: only close ch if it's still the
		// current deadline channel AND not already closed. Without this
		// guard, setDl(t1) → setDl(t2) closes ch1 inline, then ch1's
		// orphan timer fires and panics with "close of closed channel".
		// Observed 2026-05-20 on the server side simultaneously with
		// the iOS-side wrappedConn variant — same bug pattern.
		time.AfterFunc(dur, func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.dlCh != ch {
				return
			}
			select {
			case <-ch:
			default:
				close(ch)
			}
		})
	}
}

// ─── wrappedConn — the SRTP-encrypted net.Conn ────────────────────────────

type wrappedConn struct {
	underlay net.PacketConn
	remote   net.Addr
	dtlsConn *dtls.Conn
	encCtx   *srtp.Context
	decCtx   *srtp.Context

	rxCh chan []byte
	ssrc uint32

	mu  sync.Mutex
	seq uint16
	ts  uint32

	closeOnce sync.Once
	closed    chan struct{}
	onClose   func()

	dlMu  sync.Mutex
	dlExp time.Time
	dlCh  chan struct{}

	// stopDemux is set on the client side so Close() unwinds the
	// background packet demux goroutine.
	stopDemux func()

	// Per-side reusable scratch buffers. See iOS-side pkg/proxy/
	// srtpwrap for the long explanation. Cuts ~4 allocs per packet
	// (DecryptRTP output, MarshalTo target, EncryptRTP output, plus
	// pion's internal small allocations). Safe without mutex because
	// the pumpBidirectional goroutines in main.go dedicate one
	// goroutine to Read and one to Write per net.Conn.
	rxDecBuf     []byte
	txMarshalBuf []byte
	txEncBuf     []byte
}

func newWrappedConn(underlay net.PacketConn, remote net.Addr, dconn *dtls.Conn,
	rxCh chan []byte, isClient bool, stopDemux func(),
) (*wrappedConn, error) {
	state, ok := dconn.ConnectionState()
	if !ok {
		return nil, errors.New("srtpwrap: dtls connection state unavailable")
	}

	cfg := &srtp.Config{Profile: srtp.ProtectionProfileAes128CmHmacSha1_80}
	if err := cfg.ExtractSessionKeysFromDTLS(&state, isClient); err != nil {
		return nil, fmt.Errorf("srtpwrap: extract session keys: %w", err)
	}

	encCtx, err := srtp.CreateContext(cfg.Keys.LocalMasterKey, cfg.Keys.LocalMasterSalt, cfg.Profile)
	if err != nil {
		return nil, fmt.Errorf("srtpwrap: enc context: %w", err)
	}
	decCtx, err := srtp.CreateContext(cfg.Keys.RemoteMasterKey, cfg.Keys.RemoteMasterSalt, cfg.Profile)
	if err != nil {
		return nil, fmt.Errorf("srtpwrap: dec context: %w", err)
	}

	var ssrcB [4]byte
	if _, err := rand.Read(ssrcB[:]); err != nil {
		return nil, fmt.Errorf("srtpwrap: ssrc random: %w", err)
	}

	return &wrappedConn{
		underlay:  underlay,
		remote:    remote,
		dtlsConn:  dconn,
		encCtx:    encCtx,
		decCtx:    decCtx,
		rxCh:      rxCh,
		ssrc:      binary.BigEndian.Uint32(ssrcB[:]),
		closed:    make(chan struct{}),
		stopDemux: stopDemux,
	}, nil
}

func (c *wrappedConn) Read(b []byte) (int, error) {
	for {
		dl := c.deadlineCh()
		select {
		case pkt, ok := <-c.rxCh:
			if !ok {
				return 0, net.ErrClosed
			}
			// Reuse c.rxDecBuf — see iOS-side srtpwrap for rationale.
			if cap(c.rxDecBuf) < len(pkt) {
				c.rxDecBuf = make([]byte, 0, len(pkt)+64)
			}
			plain, err := c.decCtx.DecryptRTP(c.rxDecBuf[:0], pkt, nil)
			if err != nil {
				continue
			}
			c.rxDecBuf = plain[:0]
			var hdr rtp.Header
			n, err := hdr.Unmarshal(plain)
			if err != nil {
				continue
			}
			return copy(b, plain[n:]), nil
		case <-c.closed:
			return 0, net.ErrClosed
		case <-dl:
			if c.deadlineExpired() {
				return 0, os.ErrDeadlineExceeded
			}
		}
	}
}

func (c *wrappedConn) Write(b []byte) (int, error) {
	// Lock held for the entire method, not just the seq/ts increment.
	// Mirror of the client-side fix in cacggghp/vk-turn-proxy-ios
	// pkg/proxy/srtpwrap/srtp.go: pion's srtp.Context.EncryptRTP is
	// NOT safe for concurrent use (HMAC-SHA1 keeps internal state across
	// Sum() calls), and the per-conn scratch buffers (txMarshalBuf,
	// txEncBuf) cannot be safely shared between Write callers either.
	// Server-side pumpBidirectional currently has only one writer per
	// wrappedConn, so this race is not actively triggered today — but
	// holding the lock through the entire Write is defensive against
	// any future caller that adds a second writer (e.g. server-side
	// probe-back, multi-stream multiplexing). The client side hit this
	// race in build 125 production after the probe sender goroutine
	// was added — see the iOS commit for the full panic stack.
	c.mu.Lock()
	defer c.mu.Unlock()

	seq := c.seq
	ts := c.ts
	c.seq++
	c.ts += uint32(len(b))

	pkt := rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    PayloadType,
			SequenceNumber: seq,
			Timestamp:      ts,
			SSRC:           c.ssrc,
		},
		Payload: b,
	}
	// Reuse c.txMarshalBuf and c.txEncBuf — see iOS-side srtpwrap.
	needSize := pkt.MarshalSize()
	if cap(c.txMarshalBuf) < needSize {
		c.txMarshalBuf = make([]byte, needSize+64)
	}
	rawLen, err := pkt.MarshalTo(c.txMarshalBuf[:needSize])
	if err != nil {
		return 0, fmt.Errorf("rtp marshal: %w", err)
	}
	raw := c.txMarshalBuf[:rawLen]
	encSize := rawLen + 16
	if cap(c.txEncBuf) < encSize {
		c.txEncBuf = make([]byte, 0, encSize+64)
	}
	enc, err := c.encCtx.EncryptRTP(c.txEncBuf[:0], raw, nil)
	if err != nil {
		return 0, fmt.Errorf("srtp encrypt: %w", err)
	}
	c.txEncBuf = enc[:0]
	if _, err := c.underlay.WriteTo(enc, c.remote); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wrappedConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.onClose != nil {
			c.onClose()
		}
		if c.dtlsConn != nil {
			err = c.dtlsConn.Close()
		}
		if c.stopDemux != nil {
			c.stopDemux()
		}
	})
	return err
}

func (c *wrappedConn) LocalAddr() net.Addr  { return c.underlay.LocalAddr() }
func (c *wrappedConn) RemoteAddr() net.Addr { return c.remote }

func (c *wrappedConn) SetDeadline(t time.Time) error {
	c.setDl(t)
	return nil
}
func (c *wrappedConn) SetReadDeadline(t time.Time) error {
	c.setDl(t)
	return nil
}
func (c *wrappedConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *wrappedConn) deadlineCh() <-chan struct{} {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.dlCh == nil {
		c.dlCh = make(chan struct{})
	}
	return c.dlCh
}

func (c *wrappedConn) deadlineExpired() bool {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	return !c.dlExp.IsZero() && !time.Now().Before(c.dlExp)
}

func (c *wrappedConn) setDl(t time.Time) {
	c.dlMu.Lock()
	defer c.dlMu.Unlock()
	if c.dlCh != nil {
		select {
		case <-c.dlCh:
		default:
			close(c.dlCh)
		}
	}
	c.dlCh = make(chan struct{})
	c.dlExp = t
	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			close(c.dlCh)
			return
		}
		ch := c.dlCh
		// See pkg/proxy/srtpwrap setDl for the full explanation. Same
		// "close of closed channel" race: setDl(t1) → setDl(t2) closes
		// ch1 inline; later ch1's orphan timer fires and panics. Server
		// side observed crashing 2026-05-20 simultaneously with iOS
		// build 121 around T+32s of every session.
		time.AfterFunc(dur, func() {
			c.dlMu.Lock()
			defer c.dlMu.Unlock()
			if c.dlCh != ch {
				return
			}
			select {
			case <-ch:
			default:
				close(ch)
			}
		})
	}
}

// ─── client-side demux from a single-peer PacketConn ──────────────────────

func runDemuxFromPacketConn(ctx context.Context, raw net.PacketConn, dtlsCh, rtpCh chan<- []byte) {
	// See iOS pkg/proxy/srtpwrap/srtp.go for the long story. tl;dr: the
	// previous 500ms-polling pattern was a CPU-wakeup-budget killer on
	// iOS Network Extension. Block on ReadFrom and use AfterFunc to set
	// the deadline only on ctx cancellation.
	stop := context.AfterFunc(ctx, func() {
		_ = raw.SetReadDeadline(time.Now())
	})
	defer stop()

	buf := make([]byte, 2048)
	for {
		n, _, err := raw.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
				_ = raw.SetReadDeadline(time.Time{})
				continue
			}
			continue
		}
		if n == 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		switch {
		case IsDTLS(pkt[0]):
			select {
			case dtlsCh <- pkt:
			case <-ctx.Done():
				return
			}
		case IsRTP(pkt[0]):
			select {
			case rtpCh <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}
}

