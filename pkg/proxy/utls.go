package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// chromeRoundTripper routes requests through HTTP/2 or HTTP/1.1 based
// on what the server negotiates via ALPN. Uses uTLS to mimic Chrome's
// TLS fingerprint for both protocols.
type chromeRoundTripper struct {
	h2 *http2.Transport // HTTP/2 transport (Chrome ALPN: h2, http/1.1)
	h1 *http.Transport  // HTTP/1.1 fallback (Chrome ALPN forced to http/1.1)
}

// newChromeTransport creates an http.RoundTripper that uses uTLS to mimic
// Chrome's TLS fingerprint and supports HTTP/2.
//
// How it works:
//  1. Tries HTTP/2 first — dials with Chrome ALPN (h2, http/1.1),
//     verifies h2 was negotiated, uses http2.Transport for framing.
//  2. Falls back to HTTP/1.1 — if h2 negotiation fails (server doesn't
//     support h2), re-dials with ALPN forced to http/1.1 only,
//     uses standard http.Transport.
//
// This gives us:
//   - Chrome JA3 fingerprint (cipher suites, extensions, key shares)
//   - Proper h2 protocol when server supports it (VK does)
//   - Automatic fallback for h1-only servers
func newChromeTransport() http.RoundTripper {
	rt := &chromeRoundTripper{}

	rt.h2 = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, err := dialChromeTLS(ctx, network, addr, false)
			if err != nil {
				return nil, err
			}
			proto := conn.ConnectionState().NegotiatedProtocol
			if proto != "h2" {
				_ = conn.Close()
				return nil, fmt.Errorf("utls: server %s negotiated %q, not h2", addr, proto)
			}
			return conn, nil
		},
	}

	rt.h1 = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialChromeTLS(ctx, network, addr, true)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConnsPerHost: 5,
	}

	return rt
}

func (rt *chromeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.h2.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	// h2 failed — fall back to h1 (re-dials with http/1.1-only ALPN)
	log.Printf("utls: h2 failed for %s: %v — falling back to h1", req.URL.Host, err)
	return rt.h1.RoundTrip(req)
}

// dialChromeTLS establishes a TLS connection using uTLS with Chrome's
// ClientHello fingerprint.
//
// If forceH1 is true, ALPN is overridden to only advertise http/1.1
// (for use with Go's http.Transport which can't handle h2 frames).
// If forceH1 is false, ALPN keeps Chrome's default: ["h2", "http/1.1"].
func dialChromeTLS(ctx context.Context, network, addr string, forceH1 bool) (*utls.UConn, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("split host:port %q: %w", addr, err)
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("get Chrome spec: %w", err)
	}

	if forceH1 {
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
				spec.Extensions[i] = alpn
				break
			}
		}
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName: host,
	}, utls.HelloCustom)

	if err := tlsConn.ApplyPreset(&spec); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("apply Chrome spec: %w", err)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake with %s: %w", host, err)
	}

	return tlsConn, nil
}
