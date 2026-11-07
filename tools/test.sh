#!/bin/sh
# The server repo's gate — run ALONE from the repo root before a commit:
#
#   1. the root module (./server, ./client, …) — go test, -race when RACE=1;
#   2. the vendored fork of pion/turn (third_party/pion-turn — the request's
#      MESSAGE-INTEGRITY check removed, for tools/turn-relay ONLY: the user's
#      own relay accepts the credentials VK issued): its guard diffs the tree
#      against pristine upstream and compares with FORK.patch, and the patched
#      server package's own tests run; a module of its own, never reached by
#      the root ./... ;
#   3. tools/turn-relay — the relay itself, a module of its own (the fork's
#      replace must never reach the server), its tests, and its builds for the
#      stands and the release's targets;
#
# Exit 0 and a PASS under every heading, or it did not pass. Moved here with
# the tool from vk-turn-proxy-ios on 2026-11-07, where tools/test.sh ran the
# same three sections.
set -u
cd "$(dirname "$0")/.." || exit 2

fail=0
run() {
    echo
    echo "══ $1"
    shift
    if "$@"; then
        echo "   PASS"
    else
        echo "   FAIL"
        fail=1
    fi
}

goflags="-count=1"
[ "${RACE:-0}" = "1" ] && goflags="$goflags -race"

run "root module — go test $goflags ./..." \
    sh -c "go test $goflags ./..."

# 🚨 The fork's guard needs pristine upstream in the module cache. It FATALS
# rather than skipping if it is cold — a guard that skips itself is a guard
# that is green everywhere it has not been set up.
UPSTREAM_TURN=github.com/pion/turn/v5@v5.0.2
echo
echo "== fetching pristine $UPSTREAM_TURN for the relay fork's guard"
if go mod download "$UPSTREAM_TURN"; then
    echo "   ready"
else
    echo "   FAIL: could not fetch $UPSTREAM_TURN -- the relay fork's guard cannot run" >&2
    fail=1
fi
# Two upstream tests are skipped: TestServerVNet/AuthEventHandlerFailure waits
# for the auth-failure event a bad signature raised — the fork raises none
# (FORK.md); TestConnectRequest dials 127.0.0.1:5000 expecting a refusal, and
# on a Mac with the AirPlay receiver on that port answers.
run "vendored fork of pion/turn — the guard and the patched packages" \
    sh -c "cd third_party/pion-turn && go test $goflags -skip 'TestConnectRequest|TestServerVNet/AuthEventHandlerFailure' . ./internal/server/"

run "turn-relay — the relay for the user's own-relay scheme (issue #105)" \
    sh -c "cd tools/turn-relay && go test $goflags ."
relay_targets() {
    ok=0
    # The release builds it for these (release.yml); the stands are among them.
    for t in linux/amd64 linux/arm64 linux/386 linux/arm darwin/amd64 darwin/arm64 freebsd/amd64; do
        (cd tools/turn-relay && CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -trimpath -o /dev/null .) \
            || { echo "   build $t failed"; ok=1; }
    done
    # The tool's TESTS compile for the Linux stands too: a socket option the
    # Mac's syscall package has and Linux's lacks broke them once (2026-11-01).
    (cd tools/turn-relay && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o /dev/null .) \
        || { echo "   test build linux/amd64 failed"; ok=1; }
    return $ok
}
run "turn-relay — built for the release's targets and the stands" \
    relay_targets

echo
if [ "$fail" = 0 ]; then
    echo "ALL PASS"
else
    echo "SOMETHING FAILED (see the FAIL lines above)"
fi
exit "$fail"
