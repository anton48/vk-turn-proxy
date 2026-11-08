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
// bytes, the four magic bytes, the client's connection index behind them and
// the session's generation behind that (uint16 and uint64, big-endian).
func isGroupReplace(buf []byte) (idx uint16, gen uint64, ok bool) {
	if len(buf) != groupHelloLen {
		return 0, 0, false
	}
	for i, b := range groupReplaceMagic {
		if buf[i] != b {
			return 0, 0, false
		}
	}
	return binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint64(buf[6:14]), true
}

// hubMember: the connection holding a client index in a group, and the
// generation of the session that claimed it.
type hubMember struct {
	st     *connStat
	cancel func()
	gen    uint64
}

// claim: st, running the client's session of generation gen on index idx,
// names itself the index's holder. THE GENERATION DECIDES, NEVER THE ORDER OF
// ARRIVAL (the user's review of b1372eb): the sentinel is repeated behind every
// tick's ping and travels a UDP leg, so a late first copy of the OLD session
// could arrive behind the new session's claim, and a repeat the old session
// had read before its end could be processed after it — either would have
// ended the healthy successor. So the hub keeps the HIGHEST generation
// accepted per index (maxGen), apart from the holder and surviving its leave:
// a generation at or below it from any other connection is stale and claims
// nothing; the holder's own repeat is a no-op; only a higher generation takes
// the index — and ends the holder it displaces (its context cancelled, its
// reap reason set, the counter moved), returned here for the log. The
// generation is the client's hand-out stamp: fixed for one session, higher
// for every later session on the index.
//
// AND A STALE SENDER ENDS (the user's review of a316b3c): a claim STRICTLY
// below the bar from a connection that is not the holder comes from an older
// session of that index — one that outlived its replacement (its first copy
// late behind the successor's claim). Returning from here left it a member
// and a consumer of the group's shared queue, the very thing the sentinel is
// for: through the real pump it took 10 of the next 20 downlink packets. So
// the sender is ended through its own cancel (stale = true, for the log), the
// holder untouched; a claim AT the bar from another connection is not
// strictly older and ends nobody.
func (h *downlinkHub) claim(idx uint16, gen uint64, st *connStat, cancel func()) (prev *connStat, stale bool) {
	h.membersMu.Lock()
	if h.members == nil {
		h.members = map[uint16]hubMember{}
		h.maxGen = map[uint16]uint64{}
	}
	cur, had := h.members[idx]
	if had && cur.st == st {
		h.membersMu.Unlock()
		return nil, false // the holder's own repeat, whatever it says: never its own end
	}
	if bar, barred := h.maxGen[idx]; barred && gen <= bar {
		h.membersMu.Unlock()
		if gen == bar {
			return nil, false // at the bar from another connection: not strictly older — nothing is known about it
		}
		// STRICTLY OLDER than a session already accepted on this index, and
		// not the holder: a predecessor that outlived its replacement (the
		// user's review of a316b3c). It claims nothing — and it ENDS, here,
		// through its own cancel: left a member, it would go on taking from
		// the group's queue (10 of the next 20 downlink packets, measured)
		// until the zombie reaper. Once per connection: a copy it had read
		// before its end finds it ending already.
		if st.reaped.CompareAndSwap(int64(reapNone), int64(reapReplaced)) {
			reapsByReason[reapReplaced].Add(1)
			cancel()
			return nil, true
		}
		return nil, false
	}
	h.members[idx] = hubMember{st: st, cancel: cancel, gen: gen}
	h.maxGen[idx] = gen
	h.membersMu.Unlock()
	if !had {
		return nil, false
	}
	cur.st.reaped.Store(int64(reapReplaced))
	reapsByReason[reapReplaced].Add(1)
	cur.cancel()
	return cur.st, false
}

// leave forgets st as a holder — at its connection's end, so that a later
// claim of its index finds no predecessor and keeps no stale cancel. The
// highest generation accepted stays: a stale copy of the session that left
// must not take the index back.
func (h *downlinkHub) leave(st *connStat) {
	h.membersMu.Lock()
	defer h.membersMu.Unlock()
	for idx, m := range h.members {
		if m.st == st {
			delete(h.members, idx)
		}
	}
}

// holder: the connection holding idx now, nil when none.
func (h *downlinkHub) holder(idx uint16) *connStat {
	h.membersMu.Lock()
	defer h.membersMu.Unlock()
	if m, ok := h.members[idx]; ok {
		return m.st
	}
	return nil
}
