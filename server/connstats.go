package main

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Server-side per-connection byte counters — the mirror of the iOS client's
// `proxy: conn-stats` dump, so the two logs can be compared line for line.
//
// Why this exists (M0 of the downlink-scheduler plan): the downlink skew that
// caps download throughput has only ever been observed FROM THE PHONE. Either
// the server already hands the connections uneven shares — in which case the
// cause is upstream of the relay and ours to fix — or the server sends evenly
// and the relay creates the skew, in which case the whole scheduler plan aims
// at the wrong place. One run of this dump distinguishes the two.
//
// ⚠️ DIRECTION NAMING. The client labels its counters from its own point of
// view: TX = client→server, RX = server→client. To keep the two dumps directly
// comparable this file uses UP and DOWN with the SAME meaning:
//
//	UP   = client → WireGuard  (matches the client's TX)
//	DOWN = WireGuard → client  (matches the client's RX)  ← the axis of interest
//
// ⚠️ 60 s IS TOO COARSE ONCE YOU CARE ABOUT SHARES. A speedtest alternates
// download, upload and idle inside one interval, so a per-connection share
// computed over the whole minute is NOT the share during the download burst.
// Deriving a per-connection rate as `share × speedtest` therefore double-counts
// the burst and can produce impossible numbers — it once implied a connection
// running at 165% of its policer. Use -conn-stats-interval to get inside the
// burst, and prefer the directly logged KB/s over anything derived from shares.
var connStatsInterval = 60 * time.Second

type connStat struct {
	id     int
	remote string
	up     atomic.Int64
	down   atomic.Int64
	// Pacer instrumentation (M2b). Without these there is no way to tell a
	// pacer that is shaping the traffic from one whose rate is set so high it
	// never blocks — the two look identical in the byte counters.
	downPkts  atomic.Int64 // writes attempted on the downlink
	pacedPkts atomic.Int64 // ...of which had to wait for tokens
	pacedNs   atomic.Int64 // total time spent waiting
}

type connRegistry struct {
	mu     sync.Mutex
	nextID int
	conns  map[int]*connStat
	prevUp map[int]int64
	prevDn map[int]int64
	// Pacer deltas, same interval as the byte deltas.
	prevDnPkts map[int]int64
	prevPaced  map[int]int64
	prevPaceNs map[int]int64
}

var registry = &connRegistry{
	conns:      make(map[int]*connStat),
	prevUp:     make(map[int]int64),
	prevDn:     make(map[int]int64),
	prevDnPkts: make(map[int]int64),
	prevPaced:  make(map[int]int64),
	prevPaceNs: make(map[int]int64),
}

func (r *connRegistry) add(remote string) *connStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	c := &connStat{id: r.nextID, remote: remote}
	r.conns[c.id] = c
	return c
}

func (r *connRegistry) remove(c *connStat) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, c.id)
	delete(r.prevUp, c.id)
	delete(r.prevDn, c.id)
	delete(r.prevDnPkts, c.id)
	delete(r.prevPaced, c.id)
	delete(r.prevPaceNs, c.id)
}

// runConnStatsLoop dumps a per-connection table every connStatsInterval.
// Started unconditionally from main — it changes no behaviour.
func runConnStatsLoop(done <-chan struct{}) {
	tick := time.NewTicker(connStatsInterval)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case <-done:
			registry.dump(time.Since(last), "final")
			return
		case now := <-tick.C:
			registry.dump(now.Sub(last), "tick")
			last = now
		}
	}
}

type statRow struct {
	id           int
	remote       string
	up, dn       int64 // deltas over the interval
	upCum, dnCum int64
}

func (r *connRegistry) dump(dur time.Duration, label string) {
	if dur <= 0 {
		return
	}
	r.mu.Lock()
	rows := make([]statRow, 0, len(r.conns))
	var pacedPkts, dnPkts, paceNs int64
	for id, c := range r.conns {
		u, d := c.up.Load(), c.down.Load()
		rows = append(rows, statRow{
			id: id, remote: c.remote,
			up: u - r.prevUp[id], dn: d - r.prevDn[id],
			upCum: u, dnCum: d,
		})
		r.prevUp[id], r.prevDn[id] = u, d

		dp, pp, pn := c.downPkts.Load(), c.pacedPkts.Load(), c.pacedNs.Load()
		dnPkts += dp - r.prevDnPkts[id]
		pacedPkts += pp - r.prevPaced[id]
		paceNs += pn - r.prevPaceNs[id]
		r.prevDnPkts[id], r.prevPaced[id], r.prevPaceNs[id] = dp, pp, pn
	}
	r.mu.Unlock()

	if len(rows) == 0 {
		return
	}
	// Sorted by DOWN because that is the direction under investigation — the
	// hottest connection ends up on the first line.
	sort.Slice(rows, func(i, j int) bool { return rows[i].dn > rows[j].dn })

	secs := dur.Seconds()
	log.Printf("conn-stats %s over %.1fs (conns=%d):", label, secs, len(rows))
	for _, w := range rows {
		log.Printf("  conn %3d:  UP %s/s (%s cum)  DOWN %s/s (%s cum)  [%s]",
			w.id,
			humanBytes(int64(float64(w.up)/secs)), humanBytes(w.upCum),
			humanBytes(int64(float64(w.dn)/secs)), humanBytes(w.dnCum),
			w.remote)
	}

	// The summary line carries exactly the three numbers we otherwise work out
	// by hand from every log: the two totals, how uneven each direction is, and
	// the hottest connection's share — which is what bounds the whole tunnel,
	// since aggregate <= per-conn policer / max(share).
	var sumUp, sumDn int64
	maxDn, maxUp := int64(0), int64(0)
	minDn, minUp := int64(-1), int64(-1)
	for _, w := range rows {
		sumUp += w.up
		sumDn += w.dn
		if w.dn > maxDn {
			maxDn = w.dn
		}
		if w.up > maxUp {
			maxUp = w.up
		}
		if w.dn > 0 && (minDn < 0 || w.dn < minDn) {
			minDn = w.dn
		}
		if w.up > 0 && (minUp < 0 || w.up < minUp) {
			minUp = w.up
		}
	}
	log.Printf("  summary: ΣUP %s/s  ΣDOWN %s/s | spread DOWN %s UP %s | top DOWN share %s",
		humanBytes(int64(float64(sumUp)/secs)), humanBytes(int64(float64(sumDn)/secs)),
		ratio(maxDn, minDn), ratio(maxUp, minUp), share(maxDn, sumDn))

	// Only when pacing is on, and worth reading closely: 0 delayed writes means
	// the rate is set above what the traffic ever asks for, so the pacer is
	// present but inert and the run is NOT a test of it.
	if downlinkPaceRate > 0 {
		pct := 0.0
		if dnPkts > 0 {
			pct = 100 * float64(pacedPkts) / float64(dnPkts)
		}
		mean := time.Duration(0)
		if pacedPkts > 0 {
			mean = time.Duration(paceNs / pacedPkts)
		}
		log.Printf("  pacer: %d/%d writes delayed (%.1f%%), Σwait %s, mean wait %s",
			pacedPkts, dnPkts, pct,
			time.Duration(paceNs).Round(time.Millisecond),
			mean.Round(10*time.Microsecond))
	}
}

func ratio(max, min int64) string {
	if min <= 0 || max <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2fx", float64(max)/float64(min))
}

func share(max, sum int64) string {
	if sum <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(max)/float64(sum))
}

// humanBytes divides by powers of 1024, so the unit is KiB/MiB and it must SAY
// so. It used to print "KB"/"MB" against those divisors, and two independent
// analyses of the same log then spent real effort arguing 4.7% apart — one
// reading 420.30 "MB" as decimal, the other as binary. Same bytes, two
// conventions, no way to tell from the line. Label the unit you actually used.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
