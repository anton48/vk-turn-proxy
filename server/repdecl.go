package main

import "encoding/binary"

// THE REPLACEMENT SENTINEL (2026-11-08, the failover run on build 477 — Nov 8
// §603). The client re-dials a session the moment its relay is marked
// UNREACHABLE (build 477: the forty back within 1.5 s of the mark), but the
// server learns nothing of the predecessor: its TCP connection is black-holed
// on the relay side, so no close arrives, and the member lives in the group
// until the zombie reaper (90 s of silence beside heard neighbours). Meanwhile
// the downlink hub hands each packet to whichever member's goroutine has waited
// LONGEST on the shared channel (downlink.go — a channel's receivers are a
// FIFO), and the dead members, queued since the black-out, take the next ≈40
// packets — WireGuard's handshake responses, the SYN-ACKs — before a live one
// gets a turn: ≈28 s of a deaf tunnel, the first download after the failover
// timed out (observed 10:43–10:44 MSK, 2026-11-08).
//
// So the client NAMES the connection it replaces: behind the hello of every
// new session, and again behind every tick's ping (a lost copy heals by
// repetition — the relay → server leg is UDP), a 20-byte sentinel of the
// hello's construction, 0xff 'R' 'E' 'P' + the client's connection index
// (uint16, big-endian), zero-padded. The server keeps, per group, which member
// holds each index; a claim by another member ENDS the holder at once (its
// goroutine leaves the channel's queue, its seat and declaration go with it);
// a repeat from the holder itself is a no-op; a claim before the hello (the
// two can swap on the UDP leg) is ignored until the next repeat. An old server
// forwards the sentinel to WireGuard, which drops it; an old client sends none.
// The pattern of the supersede sentinel (keepalive.go) and the pace declaration
// (pacedecl.go).
var groupReplaceMagic = []byte{0xff, 'R', 'E', 'P'}

// isGroupReplace recognises the replacement sentinel: exactly groupHelloLen
// bytes, the four magic bytes, the client's connection index behind them.
func isGroupReplace(buf []byte) (idx uint16, ok bool) {
	if len(buf) != groupHelloLen {
		return 0, false
	}
	for i, b := range groupReplaceMagic {
		if buf[i] != b {
			return 0, false
		}
	}
	return binary.BigEndian.Uint16(buf[4:6]), true
}

// hubMember: the connection holding a client index in a group.
type hubMember struct {
	st     *connStat
	cancel func()
}

// claim records st as the holder of the client's index idx in this group and
// returns the predecessor it displaced — ended here (its context cancelled,
// its reap reason set, the counter moved) — or nil when there was none or the
// holder is st itself (a repeat).
func (h *downlinkHub) claim(idx uint16, st *connStat, cancel func()) *connStat {
	h.membersMu.Lock()
	prev, had := h.members[idx]
	if had && prev.st == st {
		h.membersMu.Unlock()
		return nil
	}
	if h.members == nil {
		h.members = map[uint16]hubMember{}
	}
	h.members[idx] = hubMember{st: st, cancel: cancel}
	h.membersMu.Unlock()
	if !had {
		return nil
	}
	prev.st.reaped.Store(int64(reapReplaced))
	reapsByReason[reapReplaced].Add(1)
	prev.cancel()
	return prev.st
}

// leave forgets st as a holder — at its connection's end, so that a later
// claim of its index finds no predecessor and keeps no stale cancel.
func (h *downlinkHub) leave(st *connStat) {
	h.membersMu.Lock()
	defer h.membersMu.Unlock()
	for idx, m := range h.members {
		if m.st == st {
			delete(h.members, idx)
		}
	}
}
