package srtpwrap

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/srtp/v3"
)

// Each of these was SEEN to fail under a sabotage that still COMPILES; the
// sabotage is named above the test.

func resetUnwrap() {
	unwrapDelivered.Store(0)
	unwrapDecryptFail.Store(0)
	unwrapHeaderFail.Store(0)
	unwrapDetailLogs.Store(0)
}

// A packet that fails to decrypt is DROPPED, and the drop is invisible anywhere
// downstream — the loss counter observes after this Read, so the packet reads as
// a gap in the sender's counter space. The count is the only thing that can tell
// "the network lost it" from "we threw it away".
//
// 🚨 This drives the REAL Read loop rather than calling the counter directly:
// the property under test is that the error path in Read is instrumented, and a
// test that called noteUnwrapDecryptFail itself would pass with the call site
// deleted — the exact defect class this project has already paid for.
//
// SABOTAGE SEEN TO FAIL: delete the noteUnwrapDecryptFail call in Read's
// `if err != nil` branch, leaving the bare `continue`. Compiles; this test then
// reads 0 failures.
func TestDecryptFailureIsCountedOnTheRealReadPath(t *testing.T) {
	resetUnwrap()

	key := make([]byte, 16)
	salt := make([]byte, 14)
	ctx, err := srtp.CreateContext(key, salt, srtp.ProtectionProfileAes128CmHmacSha1_80)
	if err != nil {
		t.Fatalf("CreateContext: %v", err)
	}

	c := &wrappedConn{
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		decCtx: ctx,
		rxCh:   make(chan []byte, 4),
		closed: make(chan struct{}),
	}

	// Version-2 RTP first byte so the packet reaches DecryptRTP the way a real
	// one does; the rest is garbage, so authentication fails.
	pkt := pktPoolGet(64)
	pkt[0] = 0x80
	c.rxCh <- pkt

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		_, _ = c.Read(buf) // returns once `closed` is closed
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for unwrapDecryptFail.Load() == 0 {
		select {
		case <-deadline:
			close(c.closed)
			<-done
			t.Fatal("a packet that failed to decrypt was dropped without being counted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(c.closed)
	<-done

	if got := unwrapDelivered.Load(); got != 0 {
		t.Fatalf("nothing was delivered, but delivered=%d", got)
	}
}

// The counters are read-and-reset, so an interval that saw nothing must not
// inherit the previous interval's failures.
//
// SABOTAGE SEEN TO FAIL: change the Swap(0) calls in UnwrapStats to Load().
// Compiles; the second read then still reports the same numbers.
func TestUnwrapStatsReadsAndResets(t *testing.T) {
	resetUnwrap()
	noteUnwrapDelivered()
	noteUnwrapDelivered()
	noteUnwrapDecryptFail(nil, 10, errors.New("x"))
	noteUnwrapHeaderFail(nil, 10, errors.New("y"))

	d, dec, hdr := UnwrapStats()
	if d != 2 || dec != 1 || hdr != 1 {
		t.Fatalf("first read: delivered=%d decrypt=%d header=%d", d, dec, hdr)
	}
	if d, dec, hdr := UnwrapStats(); d != 0 || dec != 0 || hdr != 0 {
		t.Fatalf("counters must reset: delivered=%d decrypt=%d header=%d", d, dec, hdr)
	}
}

// 🚨 A systematic failure would write one line per packet at thousands per
// second and bury the log that has to be read afterwards. The detail lines are
// budgeted; the AGGREGATE is what carries the rest, which is why the counter
// must keep counting long after the logging stops.
//
// SABOTAGE SEEN TO FAIL: move the `unwrapDecryptFail.Add(1)` inside the budget
// check in logUnwrapDetail (i.e. count only what is logged). Compiles; this test
// then reads 5 instead of 200.
func TestUnwrapDetailLoggingIsBudgetedButCountingIsNot(t *testing.T) {
	resetUnwrap()
	for i := 0; i < 200; i++ {
		noteUnwrapDecryptFail(nil, 1200, errors.New("auth"))
	}
	if got := unwrapDecryptFail.Load(); got != 200 {
		t.Fatalf("every failure must be counted, got %d", got)
	}
	if got := unwrapDetailLogs.Load(); got != 200 {
		t.Fatalf("the budget counter tracks attempts, got %d", got)
	}
}
