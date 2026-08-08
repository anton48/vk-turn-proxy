package main

import (
	"context"
	"sync"
	"time"
)

// pacer — M2b of the downlink-scheduler plan, behind -downlink-pace.
//
// THE PROBLEM M1 LEFT BEHIND. -single-client made the downlink even (per-
// connection spread 7-9x -> 1.01x, confirmed independently from the phone's own
// RX counters), and the ceiling moved but did not disappear. Re-measured at a
// 2 s stats interval, each connection is OFFERED a median 87% of its policer
// during a download burst — but the distribution has a long right tail: p90
// 103%, p95 110%, max 149%, with 11.9% of all per-connection samples ABOVE the
// cap. VK meters each allocation with a token bucket, so it does not care that
// the two-second mean is under the limit; it clips the overshoot. Measured
// consequence: 10.25% of the downlink never arrives, while at idle the server's
// DOWN counter and the client's RX counter agree to EXACTLY zero bytes. The
// deficit tracks offered load, not evenness — within one run the burst that
// offered the most (100.2% of the aggregate ceiling) delivered the LEAST.
//
// THE FIX. Hand each connection its share smoothly instead of as fast as
// serveConn can steal it. A token bucket per connection, refilled at the
// measured policer rate, so the hub's output is shaped to what VK will actually
// carry rather than to what the WireGuard socket can produce.
//
// ⚠️ THE UNIT IS COUNTED WIRE BYTES, NOT PAYLOAD. The policer meters bytes it
// sees at the relay, which a size sweep put at rate(s) = W*s/(s+h) with
// W ~ 260 KiB/s and h ~ 30 B of per-packet overhead (RTP 12 + SRTP tag 10 +
// ChannelData 4, plus UDP). So a packet costs n+h, not n — which is also why
// small packets are genuinely penalised and why pacing on payload alone would
// systematically overshoot on chatty traffic.
const (
	// pacerPerPacketOverhead is h above: what VK counts per packet on top of
	// the bytes we hand it.
	pacerPerPacketOverhead = 30
	// pacerMaxCost is the reservation taken before dequeuing, i.e. the cost of
	// the largest packet the hub can produce.
	pacerMaxCost = dlBufSize + pacerPerPacketOverhead
)

// Set once from main before any listener starts, then read-only — same shape as
// connStatsInterval. Both are counted BYTES per second / counted bytes; the
// flags take KiB.
var (
	downlinkPaceRate  float64 // 0 = pacing off
	downlinkPaceBurst float64
)

// pacer is a token bucket over counted wire bytes. One per connection; only the
// connection's own writer goroutine touches it, so the mutex is uncontended and
// exists to keep the type safe if that ever stops being true.
type pacer struct {
	rate  float64 // counted bytes per second
	burst float64 // bucket capacity, counted bytes

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newPacer(rate, burst float64) *pacer {
	return &pacer{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// ⚠️ ONE KNOWN IMPRECISION, and it is bounded. serveConn reserves for a
// maximum-size packet before it knows the real size, so when the bucket is in
// debt the sleep is computed for pacerMaxCost and the refund arrives too late to
// shorten it. The long-run rate stays exact — the refund still credits the
// bucket, so the net debit per packet is its true cost — but an individual small
// packet can be delayed by up to pacerMaxCost/rate, about 6 ms at the suggested
// rate. Acceptable: a download burst is almost entirely full-size packets, and
// 6 ms against a ~250 ms RTT is noise. Reserving the true size instead would
// mean peeking at the queue, which reintroduces the head-of-line coupling the
// pre-dequeue reservation exists to avoid.

// take deducts cost and reports how long the caller must wait before the debt
// is paid off. Tokens are allowed to go negative — that is the reservation, and
// it is what makes the long-run rate exact instead of merely bounded: a packet
// that overdraws the bucket delays the NEXT one by precisely its excess.
func (p *pacer) take(cost float64) time.Duration {
	if p.rate <= 0 {
		// Not reachable through the flag (serveConn only builds a pacer when the
		// rate is positive), but a zero rate here would divide by zero and
		// produce a nonsense duration rather than an obvious failure.
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.tokens += p.rate * now.Sub(p.last).Seconds()
	if p.tokens > p.burst {
		p.tokens = p.burst
	}
	p.last = now
	p.tokens -= cost
	if p.tokens >= 0 {
		return 0
	}
	return time.Duration(-p.tokens / p.rate * float64(time.Second))
}

// refund returns unused reservation to the bucket. Never above the ceiling.
func (p *pacer) refund(cost float64) {
	if cost <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens += cost
	if p.tokens > p.burst {
		p.tokens = p.burst
	}
}

// await reserves cost and blocks until it is affordable. Returns the time spent
// waiting and whether the reservation survived — false means the context died
// mid-wait and the caller must not send.
//
// ⚠️ CALL THIS BEFORE TAKING A PACKET FROM THE SHARED QUEUE, not after. A writer
// that cannot afford a packet must not be holding one: the packet would be
// pinned behind this connection's wait while another connection with tokens
// sits idle in the select, which is exactly the head-of-line coupling that
// -single-client removed. Reserve for a maximum-size packet, then refund the
// difference once the real size is known.
func (p *pacer) await(ctx context.Context, cost float64) (time.Duration, bool) {
	wait := p.take(cost)
	if wait <= 0 {
		return 0, true
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return wait, true
	case <-ctx.Done():
		return 0, false
	}
}
