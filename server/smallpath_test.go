package main

import (
	"sync"
	"testing"
)

// Restore the experiment's globals after a test, so one case cannot arm the
// path for the next — these are package-level on purpose (they are flags) and
// a leaked value would silently change what the following test measures.
func withSmallPath(t *testing.T, conns, size int) {
	t.Helper()
	oc, os := dlSmallConns, dlSmallSize
	dlSmallConns, dlSmallSize = conns, size
	dlSmallWriters.Store(0)
	dlSmallRouted.Store(0)
	dlSmallFellBack.Store(0)
	t.Cleanup(func() {
		dlSmallConns, dlSmallSize = oc, os
		dlSmallWriters.Store(0)
		dlSmallRouted.Store(0)
		dlSmallFellBack.Store(0)
	})
}

func newTestHub(depth int) *downlinkHub {
	return &downlinkHub{
		ch:      make(chan dlPacket, depth),
		smallCh: make(chan dlPacket, depth),
	}
}

// 🚨 THE DEFAULT MUST BE INERT. If this fails, every run that thinks it is a
// control is actually a treatment.
func TestOffByDefaultNothingTakesTheSmallPath(t *testing.T) {
	withSmallPath(t, 0, 160)
	h := newTestHub(4)
	dlSmallWriters.Store(4) // even with writers claiming to serve it

	if h.enqueueSmall(dlPacket{n: 64}) {
		t.Fatal("a packet took the small path while the experiment is OFF")
	}
	if len(h.smallCh) != 0 || dlSmallRouted.Load() != 0 {
		t.Fatalf("small queue/counters moved with the experiment off: len=%d routed=%d",
			len(h.smallCh), dlSmallRouted.Load())
	}
}

func TestOnlySmallPacketsTakeThePath(t *testing.T) {
	withSmallPath(t, 2, 160)
	h := newTestHub(8)
	dlSmallWriters.Store(1)

	if !h.enqueueSmall(dlPacket{n: 96}) { // a bare ACK + WireGuard's 32
		t.Fatal("an ACK-sized packet did not take the small path")
	}
	if !h.enqueueSmall(dlPacket{n: 160}) { // exactly at the threshold
		t.Fatal("a packet exactly at the threshold was rejected; the bound must be inclusive")
	}
	if h.enqueueSmall(dlPacket{n: 161}) {
		t.Fatal("a packet one byte over the threshold took the small path")
	}
	if h.enqueueSmall(dlPacket{n: 1344}) { // a full data packet
		t.Fatal("a DATA packet took the ACK path — the experiment would be testing something else entirely")
	}
	if got := dlSmallRouted.Load(); got != 2 {
		t.Fatalf("routed = %d, want 2", got)
	}
}

// With no writer serving it the queue would never drain, so nothing may enter.
func TestNoWriterMeansNoSmallPath(t *testing.T) {
	withSmallPath(t, 2, 160)
	h := newTestHub(4)
	dlSmallWriters.Store(0)

	if h.enqueueSmall(dlPacket{n: 64}) {
		t.Fatal("a packet entered the small queue with nobody serving it — it would sit there forever")
	}
}

// 🚨 THE ONE THAT MATTERS FOR SAFETY. A full small queue must fall back, not
// block: the alternative is the entire downlink stalling behind it.
func TestAFullSmallQueueFallsBackInsteadOfStalling(t *testing.T) {
	withSmallPath(t, 1, 160)
	h := newTestHub(2)
	dlSmallWriters.Store(1)

	for i := 0; i < 2; i++ {
		if !h.enqueueSmall(dlPacket{n: 64}) {
			t.Fatalf("packet %d should have fitted in the small queue", i)
		}
	}
	// Third one: queue is full.
	done := make(chan bool, 1)
	go func() { done <- h.enqueueSmall(dlPacket{n: 64}) }()
	select {
	case took := <-done:
		if took {
			t.Fatal("the small queue accepted a third packet with capacity 2")
		}
	case <-make(chan struct{}):
	}
	if got := dlSmallFellBack.Load(); got != 1 {
		t.Fatalf("fell back = %d, want 1 — a fallback that is not counted is invisible in the log", got)
	}
}

// Thirty connections start within a couple of hundred ms of each other. If the
// cap leaks under that race the fan-out widens and the run silently measures a
// weaker treatment than the flag says.
func TestTheWriterSlotCapHoldsUnderConcurrentClaims(t *testing.T) {
	withSmallPath(t, 4, 160)

	var wg sync.WaitGroup
	var claimed int64
	var mu sync.Mutex
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimSmallSlot() {
				mu.Lock()
				claimed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if claimed != 4 {
		t.Fatalf("%d writers claimed a slot, want exactly 4", claimed)
	}
	if got := dlSmallWriters.Load(); got != 4 {
		t.Fatalf("dlSmallWriters = %d, want 4", got)
	}
}

func TestSlotsAreReleasedWhenAWriterLeaves(t *testing.T) {
	withSmallPath(t, 2, 160)

	if !claimSmallSlot() || !claimSmallSlot() {
		t.Fatal("the first two claims should succeed")
	}
	if claimSmallSlot() {
		t.Fatal("a third claim succeeded against a cap of 2")
	}
	dlSmallWriters.Add(-1) // one connection dies
	if !claimSmallSlot() {
		t.Fatal("the freed slot was not reusable — after enough churn nobody would serve the path")
	}
}
