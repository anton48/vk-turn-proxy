// SPDX-License-Identifier: MIT

package main

// Server-side SRTP-mimicry layer. Symmetric with the iOS client
// pkg/proxy/wrap.go — same wire format, same cipher, same constants.
// Server sets the direction-bit (MSB of sessionID/SSRC), client clears
// it. See client/wrap.go header comment for the wire format diagram
// and rationale.
//
// Wire format reference: github.com/samosvalishe/vk-turn-proxy@cd14d25
// (independent reimplementation; no code copied due to license).

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	wrapKeyLen     = 32
	wrapRTPHdrLen  = 12
	wrapNonceLen   = 12
	wrapTagLen     = 16
	wrapHeaderLen  = wrapRTPHdrLen + wrapNonceLen // 24
	wrapOverhead   = wrapHeaderLen + wrapTagLen   // 40
	wrapRTPVersion = byte(0x80)                   // V=2, P=0, X=0, CC=0
	wrapRTPPT      = byte(0x6F)                   // M=0, PT=111 (opus)
	wrapTSStep     = uint32(960)                  // 20ms @ 48kHz
)

// bufPool eliminates per-packet allocation on the hot read/write paths.
// Each pooled buffer is a pointer to a slice header so we can resize in
// place when the caller passes a larger destination. Sized for typical
// MTU + WRAP overhead — outsized packets fall back to fresh make().
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1600+wrapOverhead)
		return &b
	},
}

// wrapState holds the AEAD instance shared across all peers under one
// key. chacha20poly1305.AEAD is thread-safe — see crypto/cipher docs.
type wrapState struct {
	aead cipher.AEAD
}

func newWrapState(key []byte) (*wrapState, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: aead init: %w", err)
	}
	return &wrapState{aead: aead}, nil
}

// listenWrapped opens a UDP socket on `addr`, wraps the resulting
// PacketListener so each accepted PacketConn transparently encrypts
// outgoing writes and decrypts incoming reads via the shared `key`.
// The returned dtlsnet.PacketListener can be passed directly to
// dtls.NewListener so the DTLS layer sits ON TOP of the wrap layer
// (the wire order is: ChannelData → SRTP-mimic envelope → DTLS).
func listenWrapped(addr *net.UDPAddr, key []byte) (dtlsnet.PacketListener, error) {
	ws, err := newWrapState(key)
	if err != nil {
		return nil, err
	}
	inner, err := pionudp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp listen: %w", err)
	}
	return &wrapPacketListener{
		inner: dtlsnet.PacketListenerFromListener(inner),
		ws:    ws,
	}, nil
}

// wrapPacketListener accepts inner PacketConns and produces wrapped
// counterparts that translate every Read/Write through the SRTP-mimic
// envelope.
type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	ws    *wrapState
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	c := &wrapPacketConn{inner: pc, ws: l.ws}

	// One rand.Read for sessionID + SSRC + seq + ts (14 bytes used).
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, addr, fmt.Errorf("wrap: rand init: %w", err)
	}
	copy(c.sessionID[:], rnd[0:4])
	copy(c.ssrc[:], rnd[4:8])
	// Server always sets the direction-bit MSB to 1 (clients clear it).
	c.sessionID[0] |= 0x80
	c.ssrc[0] |= 0x80
	c.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	c.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))

	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, addr, fmt.Errorf("wrap: counter rand: %w", err)
	}
	c.counter.Store(binary.BigEndian.Uint64(cb[:]))
	return c, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

// wrapPacketConn is one wrapped PacketConn — owns per-peer cipher
// state (seq, ts, SSRC, sessionID, counter) and reuses the shared AEAD
// from wrapState for every Read/Write.
type wrapPacketConn struct {
	inner     net.PacketConn
	ws        *wrapState
	sessionID [4]byte
	ssrc      [4]byte
	counter   atomic.Uint64
	seq       atomic.Uint32 // RTP seq lives in low 16 bits
	timestamp atomic.Uint32 // full 32 bits
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bp := bufPool.Get().(*[]byte) //nolint:errcheck // pool New always returns *[]byte
	buf := *bp
	need := len(p) + wrapOverhead
	if cap(buf) < need {
		buf = make([]byte, need)
		*bp = buf
	}
	defer bufPool.Put(bp)

	n, addr, err := c.inner.ReadFrom(buf[:cap(buf)])
	if err != nil {
		return 0, addr, err
	}
	wire := buf[:n]
	if len(wire) < wrapOverhead {
		return 0, addr, errors.New("wrap: packet too short")
	}
	nonce := wire[wrapRTPHdrLen : wrapRTPHdrLen+wrapNonceLen]
	aad := wire[:wrapHeaderLen]
	ct := wire[wrapHeaderLen:]

	// Open in-place over the ciphertext region. Result is the plaintext
	// prefix of `ct` (always shorter than ct itself by exactly wrapTagLen).
	plain, err := c.ws.aead.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		return 0, addr, fmt.Errorf("wrap: AEAD open: %w", err)
	}
	if len(plain) > len(p) {
		return 0, addr, errors.New("wrap: dst buffer too small")
	}
	copy(p[:len(plain)], plain)
	return len(plain), addr, nil
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	wireLen := wrapOverhead + len(p)

	bp := bufPool.Get().(*[]byte) //nolint:errcheck // pool New always returns *[]byte
	out := *bp
	if cap(out) < wireLen {
		out = make([]byte, wireLen)
		*bp = out
	}
	out = out[:wireLen]
	defer bufPool.Put(bp)

	// RTP header.
	out[0] = wrapRTPVersion
	out[1] = wrapRTPPT
	seq := uint16(c.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(out[2:4], seq)
	ts := c.timestamp.Add(wrapTSStep) - wrapTSStep
	binary.BigEndian.PutUint32(out[4:8], ts)
	copy(out[8:12], c.ssrc[:])

	// Explicit nonce.
	noncePos := wrapRTPHdrLen
	copy(out[noncePos:noncePos+4], c.sessionID[:])
	ctr := c.counter.Add(1) - 1
	binary.BigEndian.PutUint64(out[noncePos+4:noncePos+wrapNonceLen], ctr)

	nonce := out[noncePos : noncePos+wrapNonceLen]
	aad := out[:wrapHeaderLen]
	ctPos := wrapHeaderLen
	copy(out[ctPos:], p)
	c.ws.aead.Seal(out[ctPos:ctPos], nonce, out[ctPos:ctPos+len(p)], aad)

	if _, err := c.inner.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// --- Key management helpers (server-only) ---

// genWrapKeyHex returns a freshly generated 32-byte key encoded as 64
// hex characters. Used by the -gen-wrap-key utility flag.
func genWrapKeyHex() (string, error) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("wrap: key gen: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// decodeWrapKey parses the operator's -wrap-key value. Returns
// (nil, nil) when wrap mode is not enabled so callers don't need to
// special-case the disabled path.
func decodeWrapKey(enabled bool, raw string) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	if raw == "" {
		return nil, errors.New("-wrap-srtp requires -wrap-key")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("-wrap-key invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("-wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(key))
	}
	return key, nil
}
