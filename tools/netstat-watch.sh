#!/bin/sh
# netstat-watch.sh — sample the downlink hub's UDP receive queue and the kernel's
# UDP drop counter while a measurement run is in progress. FreeBSD, POSIX sh.
#
# WHY THIS EXISTS. The hub reads every connection's downlink through ONE socket
# toward WireGuard, and those bytes are counted only AFTER conn.Write succeeds.
# A packet the kernel drops because that socket's receive buffer was full is
# therefore invisible to the server's DOWN counter and to the delivered-vs-
# offered ratio — which is why that ratio can read 100.00% while throughput is
# still being lost. Measured 2026-08-08 by hand: Recv-Q peaked at 41168 B against
# a 42080 B net.inet.udp.recvspace default while udp "dropped due to full socket
# buffers" climbed by 28196 over one run. This automates that observation and
# adds a TIME SERIES, so drops can be lined up against the server's conn-stats
# ticks instead of only compared as run totals.
#
# Timestamps are the SERVER clock, matching the server log. The phone's log runs
# on a different clock — check the offset before aligning them.
#
# Usage:
#   ./netstat-watch.sh [-d seconds] [-i interval] [-p wgport] [-o outfile]
#     -d  stop after this many seconds (default: run until Ctrl-C)
#     -i  sample interval in seconds, fractional allowed (default 0.5)
#     -p  the WireGuard port the hub dials (default 51820)
#     -o  output file (default ./netstat-watch.<date>.txt)
#
# Run it for the whole session — start it, do the speedtests, Ctrl-C. It prints
# a summary and leaves the raw samples in the output file.

set -u

DUR=""
INTERVAL=0.5
WGPORT=51820
OUT=""

while getopts "d:i:p:o:h" opt; do
	case "$opt" in
	d) DUR=$OPTARG ;;
	i) INTERVAL=$OPTARG ;;
	p) WGPORT=$OPTARG ;;
	o) OUT=$OPTARG ;;
	h)
		sed -n '2,30p' "$0"
		exit 0
		;;
	*)
		echo "try -h" >&2
		exit 2
		;;
	esac
done

[ -n "$OUT" ] || OUT="./netstat-watch.$(date '+%Y%m%d-%H%M%S').txt"
SAMPLES="$OUT.samples"

# The hub's socket is the CONNECTED one: foreign address is <wgport>, local
# address is an ephemeral port rather than a wildcard. WireGuard's own listening
# sockets show up as "*.<wgport>" in the local column and must not be counted.
hub_recvq() {
	netstat -an -p udp 2>/dev/null |
		awk -v p=".$WGPORT" '$5 != "" && index($5, p) == length($5) - length(p) + 1 && substr($4,1,1) != "*" { print $2 }'
}

udp_drops() {
	netstat -sp udp 2>/dev/null |
		awk '/dropped due to full socket buffers/ { print $1; found=1 } END { if (!found) print "" }'
}

udp_stats_snapshot() {
	netstat -sp udp 2>/dev/null |
		grep -Ei 'dropped|full socket|no socket|received|delivered' || true
}

log() { printf '%s\n' "$*" >>"$OUT"; }

{
	echo "=== netstat-watch ==="
	echo "started:  $(date '+%Y-%m-%d %H:%M:%S %Z')  (SERVER clock — matches the server log)"
	echo "host:     $(hostname)"
	echo "args:     interval=${INTERVAL}s duration=${DUR:-until-Ctrl-C} wgport=$WGPORT"
	echo
	echo "--- sysctls that bound this ---"
	sysctl kern.ipc.maxsockbuf net.inet.udp.recvspace net.inet.udp.maxdgram 2>/dev/null
	echo
	echo "--- hub socket at start ---"
	netstat -an -p udp | awk -v p="$WGPORT" 'NR==1 || index($0, p)'
	echo
	echo "--- udp stats BEFORE ---"
	udp_stats_snapshot
	echo
} >"$OUT"

BEFORE_DROPS=$(udp_drops)
: >"$SAMPLES"

echo "netstat-watch: sampling every ${INTERVAL}s -> $OUT"
echo "netstat-watch: hub socket = the one with foreign address *.$WGPORT and a non-wildcard local port"
if [ -n "$DUR" ]; then
	echo "netstat-watch: will stop automatically after ${DUR}s"
else
	echo "netstat-watch: press Ctrl-C when the run is finished"
fi

# Summary runs from the EXIT trap, not from an INT/TERM handler. A handler
# hung on INT/TERM alone is easy to get wrong — a shell blocked in sleep, or a
# job started in the background (where POSIX has the shell ignore SIGINT before
# exec, so a later trap for it never fires), and the run ends with samples on
# disk and no summary. EXIT covers every path: -d expiry, Ctrl-C, kill.
DONE=0
finish() {
	[ "$DONE" = 1 ] && return 0
	DONE=1
	NOW_DROPS=$(udp_drops)
	{
		echo
		echo "--- udp stats AFTER ---"
		udp_stats_snapshot
		echo
		echo "--- hub socket at end ---"
		netstat -an -p udp | awk -v p="$WGPORT" 'NR==1 || index($0, p)'
		echo
		echo "stopped:  $(date '+%Y-%m-%d %H:%M:%S %Z')"
	} >>"$OUT"

	echo
	echo "================ SUMMARY ================"

	if [ -n "$BEFORE_DROPS" ] && [ -n "$NOW_DROPS" ]; then
		DELTA=$((NOW_DROPS - BEFORE_DROPS))
		echo "udp 'dropped due to full socket buffers': +$DELTA over the run"
		echo "  ⚠️  host-wide counter — other sockets contribute. Read it together"
		echo "      with the Recv-Q line below, which IS this socket only."
		log ""
		log "dropped-due-to-full-socket-buffers delta: +$DELTA"
	else
		echo "udp drop counter: not found in netstat output (unexpected on FreeBSD)"
	fi

	awk '
	{ n++; q=$3+0; if (q>0) nz++; if (q>max) { max=q; maxt=$1" "$2 }; sum+=q }
	END {
		if (n == 0) { print "Recv-Q: no samples taken"; exit }
		printf "Recv-Q on the hub socket: %d samples, %d non-zero (%.1f%%)\n", n, nz, 100*nz/n
		if (max == 0) {
			print "  max 0 B"
			print "  ✅ never backed up — the receive buffer is not a bottleneck in this run"
		} else {
			printf "  max %d B at %s   mean %.0f B\n", max, maxt, sum/n
			printf "  ⚠️  backed up; compare max against net.inet.udp.recvspace above.\n"
			printf "      A max within ~5%% of the buffer means it was hitting the ceiling,\n"
			printf "      and the packets that did not fit are NOT in the DOWN counter.\n"
		}
	}' "$SAMPLES" | tee -a "$OUT"

	echo "========================================="
	echo "raw samples: $SAMPLES   (columns: date time recvq)"
	echo "full log:    $OUT"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

START=$(date +%s)
while :; do
	TS=$(date '+%Y-%m-%d %H:%M:%S')
	# Sum across matching sockets: normally exactly one, but a restarted server
	# can briefly leave two, and silently reporting only the first would hide it.
	Q=$(hub_recvq | awk '{ s += $1 } END { print s+0 }')
	printf '%s %s\n' "$TS" "$Q" >>"$SAMPLES"
	if [ -n "$DUR" ] && [ $(($(date +%s) - START)) -ge "$DUR" ]; then
		exit 0 # the EXIT trap prints the summary
	fi
	sleep "$INTERVAL"
done
