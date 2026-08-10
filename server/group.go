package main

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"time"
)

// M3 of the downlink-scheduler plan: group a client's connections so the
// shared-socket scheduler is safe with more than one client connected.
//
// THE PROBLEM -single-client LEFT. M1 put every connection on ONE socket toward
// WireGuard so the peer endpoint stops moving, and M2b paced the return path.
// Both are correct for a single client and WRONG for two: connection A's
// downlink would be sprayed across connection B's sockets and dropped by B's
// WireGuard on the keypair. That is why -single-client is an experiment flag.
//
// THE FIX. The client stamps every connection with a per-tunnel session UUID in
// an ephemeral hello, and the server keeps one hub per UUID. Grouping is all we
// need — WireGuard already carries the client's identity, so unlike qWDTT (whose
// RAW clients have no address until the server issues one) there is no device
// database, no address pool and no password here.
//
// ⚠️ THREE PROPERTIES THAT ARE LOAD-BEARING, not incidental:
//
//  1. The hello is accepted at ANY time, not only as the first packet. The
//     server already scans every packet for the probe sentinel, so a second
//     check is free — and a lost hello then heals by simple repetition instead
//     of stranding a connection in per-conn mode for the rest of the session.
//
//  2. A connection starts in per-conn mode and is PROMOTED when its hello
//     arrives. The server must never wait for a hello, because a client that
//     predates this code will never send one and would hang. That is what makes
//     old client + new server behave exactly as it does today.
//
//  3. 0xff as the first byte is outside WireGuard's 1..4 message-type range, so
//     a server that predates this code forwards the hello to its WireGuard,
//     which drops it as malformed. New client + old server therefore costs one
//     dropped 20-byte packet per probe interval and nothing else. This is the
//     same construction as the probe sentinel, in production since May.
var groupHelloMagic = []byte{0xff, 'G', 'R', 'P'}

const (
	// groupIDLen is the session UUID's length. The hello is magic+ID.
	groupIDLen = 16
	// groupHelloLen is the exact wire length; anything else is not a hello.
	groupHelloLen = 4 + groupIDLen
)

// groupIdleTimeout is the server-side backstop for a ZOMBIE connection — one
// whose TCP has not failed yet, so conn.Write still "succeeds", while the client
// behind it is gone. Such a connection keeps stealing packets from its group's
// shared queue and dropping them on the floor, which is the failure qWDTT
// documents as poisoning round-robin for the whole device.
//
// The client probes every 30 s on every connection, so any live connection
// produces inbound traffic at least that often. 150 s is deliberately LATER than
// the client's own 120 s zombie threshold: the client has better information and
// should kill first; this is only for when the client vanished entirely and
// nothing else will ever tell us.
//
// Vars rather than consts so tests can shrink them; nothing else writes these.
var (
	groupIdleTimeout = 150 * time.Second
	groupReapEvery   = 15 * time.Second
)

// isGroupHello reports whether buf is a group hello and returns its session ID.
func isGroupHello(buf []byte) (groupKey, bool) {
	var k groupKey
	if len(buf) != groupHelloLen {
		return k, false
	}
	for i, b := range groupHelloMagic {
		if buf[i] != b {
			return k, false
		}
	}
	copy(k[:], buf[4:groupHelloLen])
	return k, true
}

type groupKey [groupIDLen]byte

func (k groupKey) String() string { return hex.EncodeToString(k[:]) }

// label identifies this group in log lines. Spelling the legacy key out beats
// printing 32 zeros, and everything else matches the `group %s:` lines exactly
// so the two can be joined by grep.
func (k groupKey) label() string {
	if k == legacyGroupKey {
		return "legacy"
	}
	return k.String()
}

// legacyGroupKey is the group that ungrouped connections join when
// -single-client is set. It cannot collide with a real session UUID because the
// client draws that from crypto/rand; an all-zero draw is not worth guarding.
var legacyGroupKey = groupKey{}

// hubRegistry owns one downlinkHub per group, reference-counted by the
// connections using it. The hub outlives individual connections but must NOT
// outlive the group: its socket is what WireGuard roams onto, so leaking one
// per disconnected client would leave WireGuard pointed at a dead endpoint.
type hubRegistry struct {
	mu   sync.Mutex
	hubs map[groupKey]*hubEntry
}

type hubEntry struct {
	hub    *downlinkHub
	cancel context.CancelFunc
	refs   int
}

var groups = &hubRegistry{hubs: make(map[groupKey]*hubEntry)}

// acquire returns the group's hub, creating it on first use. Every successful
// acquire must be paired with exactly one release.
func (r *hubRegistry) acquire(ctx context.Context, connect string, key groupKey) (*downlinkHub, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.hubs[key]; ok {
		e.refs++
		return e.hub, nil
	}
	hubCtx, cancel := context.WithCancel(ctx)
	h, err := newDownlinkHub(hubCtx, connect, key.label())
	if err != nil {
		cancel()
		return nil, err
	}
	r.hubs[key] = &hubEntry{hub: h, cancel: cancel, refs: 1}
	log.Printf("group %s: opened a shared socket to %s (%d group(s) now)",
		key, connect, len(r.hubs))
	return h, nil
}

func (r *hubRegistry) release(key groupKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.hubs[key]
	if !ok {
		return
	}
	e.refs--
	if e.refs > 0 {
		return
	}
	delete(r.hubs, key)
	e.cancel()
	log.Printf("group %s: last connection gone, socket closed (%d group(s) left)",
		key, len(r.hubs))
}

// binding is what a connection currently forwards through. It is swapped at
// most once per connection, when a group hello arrives, and both the inbound
// and outbound goroutines read it — hence the atomic rather than a mutex on a
// per-packet path.
type binding struct {
	hub *downlinkHub // nil = per-conn mode
	key groupKey     // valid only when hub != nil
	wg  net.Conn     // where uplink is written: the private socket, or the hub's
}
