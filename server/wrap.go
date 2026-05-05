// SPDX-License-Identifier: MIT

package main

// Optional WRAP layer for the DTLS-over-TURN data path.
//
// Background: VK's TURN relays run a payload classifier that detects
// DTLS+WireGuard traffic patterns inside ChannelData and tags the
// destination (peer_ip, peer_port) endpoint, after which all traffic
// to that endpoint is throttled to ~9 KB/s per allocation forever.
// Tagging is triggered within minutes of the first real DTLS+WG
// client connecting; a fresh endpoint stays clean only as long as
// recognisable DTLS bytes never reach it.
//
// This file adds a thin obfuscation layer between the wire (TURN
// ChannelData payload) and the DTLS layer. Each UDP datagram on
// the wire becomes:
//
//   [12-byte random nonce] [ChaCha20-XOR(key, nonce, dtls_record_bytes)]
//
// The classifier sees pseudo-random bytes for the entire payload,
// no DTLS magic byte (0x14-0x17) at any fixed offset, no recognisable
// handshake structure. ChaCha20 with no auth tag (XOR-stream only) —
// integrity is provided by the DTLS layer underneath, we only need
// confidentiality / unrecognisability here. ~1% bandwidth overhead.
//
// Activated by the server's -wrap flag. When off, the data path is
// unchanged — backward-compatible with all existing clients. When on,
// only clients with matching wrap-key configured will succeed; old
// clients connecting to a -wrap listener will fail their DTLS handshake
// because their plain DTLS bytes get XOR'd by the listener and produce
// garbage from the DTLS state machine's perspective. Recommended
// deployment: bind a fresh port for the wrap listener and leave the
// existing port serving legacy clients without disruption.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
	"golang.org/x/crypto/chacha20"
)

const (
	// wrapNonceLen is the per-packet nonce length in bytes. ChaCha20
	// requires 12 bytes. Prepended to every wire packet.
	wrapNonceLen = 12

	// wrapKeyLen is the ChaCha20 key length in bytes (256-bit).
	wrapKeyLen = 32
)

// listenWrapped builds the listener chain:
//
//	net.ListenUDP -> pion/transport udp.Listen (per-remote demux)
//	             -> dtlsnet.PacketListenerFromListener (Conn -> PacketConn)
//	             -> wrapPacketListener (intercept Accept, wrap each PacketConn)
//
// The returned dtlsnet.PacketListener can be passed straight to
// dtls.NewListenerWithOptions and the DTLS layer above is none the wiser.
func listenWrapped(addr *net.UDPAddr, key []byte) (dtlsnet.PacketListener, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	innerListener, err := pionudp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp.Listen: %w", err)
	}
	return &wrapPacketListener{
		inner: dtlsnet.PacketListenerFromListener(innerListener),
		key:   key,
	}, nil
}

// wrapPacketListener wraps a dtlsnet.PacketListener so that every
// PacketConn returned by Accept transparently obfuscates writes and
// de-obfuscates reads through ChaCha20-XOR.
type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	key   []byte
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &wrapPacketConn{inner: pc, key: l.key}, addr, nil
}

func (l *wrapPacketListener) Close() error { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

// wrapPacketConn implements net.PacketConn by delegating to an inner
// net.PacketConn after applying ChaCha20-XOR to every packet payload.
type wrapPacketConn struct {
	inner net.PacketConn
	key   []byte
}

// ReadFrom reads one UDP datagram from inner, splits off the nonce,
// XORs the rest with ChaCha20(key, nonce), and copies the plaintext
// into p. Returns the plaintext length and the remote address.
func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Receive into a slightly larger buffer so we have room for the
	// nonce prefix in addition to whatever the caller asked for.
	buf := make([]byte, len(p)+wrapNonceLen)
	n, addr, err := c.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < wrapNonceLen {
		// Too short to contain a nonce — drop. Surface as a generic
		// short-read so the DTLS layer above just tries again.
		return 0, addr, errors.New("wrap: short packet (no nonce)")
	}
	nonce := buf[:wrapNonceLen]
	ciphertext := buf[wrapNonceLen:n]
	if len(ciphertext) > len(p) {
		// Caller's buffer too small for the plaintext. Same length as
		// ciphertext since ChaCha20 is a stream cipher.
		return 0, addr, errors.New("wrap: read buffer too small")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, nonce)
	if err != nil {
		return 0, addr, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(p[:len(ciphertext)], ciphertext)
	return len(ciphertext), addr, nil
}

// WriteTo XORs p with ChaCha20(key, nonce), prepends the nonce, and
// sends the resulting wrapped packet through inner. Returns len(p) on
// success so the caller's accounting matches the plaintext payload.
func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, wrapNonceLen+len(p))
	if _, err := rand.Read(out[:wrapNonceLen]); err != nil {
		return 0, fmt.Errorf("wrap: nonce gen: %w", err)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(c.key, out[:wrapNonceLen])
	if err != nil {
		return 0, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(out[wrapNonceLen:], p)
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
