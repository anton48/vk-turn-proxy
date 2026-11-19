# Vendored fork of `pion/turn` v5.0.2

Upstream: https://github.com/pion/turn — **MIT**, see `LICENSE` (kept verbatim;
MIT inside our GPL-3 tree, like the other Pion sources).

The whole module is vendored (every file, examples and tests included), so
that `tools/turn-relay`'s `go.mod` can `replace github.com/pion/turn/v5` with
this tree. The app and the console keep using pristine upstream from the
module cache: this fork is for the relay tool ONLY.

**TWO deliberate divergences**, guarded by `FORK.patch`:

| # | divergence | file |
|---|---|---|
| 1 | the request's MESSAGE-INTEGRITY is not checked (`authenticateRequest`) | `internal/server/util.go` |
| 2 | a request from a 5-tuple that has no allocation is ANSWERED — 400 to CreatePermission and ChannelBind, 437 to Refresh (`answerNoAllocation`) | `internal/server/util.go`, `internal/server/turn.go` |

Why: the relay stands in the TURN override list of a client that signs its
requests with the credentials VK issued — a password this server cannot know
(issue #105: the user's own relay first, VK's relays after it; the issue's
author runs the same patch). The `AuthHandler` still names the user and hands
a key for the responses, which the pion client never verifies; the nonce is
still validated. What keeps the relay from being an open one is the
`PermissionHandler` (the peers allowed) and the `QuotaHandler` (the
allocations), set by `tools/turn-relay`.

Why (2): a client behind a NAT that gave its socket a new mapping — a phone
asleep on a carrier's network — sends its refreshes from a source the server
holds no allocation for. Upstream returns `errNoAllocationFound` and sends
nothing: the client runs its whole retransmission ladder into silence and the
session above stands dead until a liveness rule finds it (a phone,
2026-11-19: minutes, for a transport with no such rule of its own). VK's
relays ANSWER such a request, and the client this relay serves ends the
session on that answer at once; the codes are theirs, as measured — 400 to
CreatePermission and ChannelBind, 437 to Refresh. The answer is sent behind
`authenticateRequest`, so only to a sender that holds a nonce of this server;
Send indications and ChannelData from such a source are still met with
silence; the error is returned to the caller as before.

Re-apply recipe (after an upstream bump): in `internal/server/util.go`,
`authenticateRequest`, replace the `stun.MessageIntegrity(ourKey).Check(…)`
block (the failed-auth event and the 400) with `_ = ourKey` and the comment
above it; keep `genAuthEvent(…, true)`. For (2): add `answerNoAllocation` to
`internal/server/util.go` and, in `internal/server/turn.go`, return it where
`handleRefreshRequest` (437), `handleCreatePermissionRequest` (400) and
`handleChannelBindRequest` (400) find no allocation. Then regenerate
`FORK.patch`:

    cd third_party/pion-turn && UPDATE_FORK_PATCH=1 go test . -run TestForkDiverges

Upstream's own tests still run in the gate (`tools/test.sh`) except
`TestServerVNet/AuthEventHandlerFailure`, which waits for the auth-failure
event a bad signature raised — the fork raises none (the test panics on its
closed channel instead of failing), and `TestConnectRequest`, an environment
flake (it dials 127.0.0.1:5000 expecting a refusal; a Mac's AirPlay receiver
answers there).

`TestForkDivergesFromUpstreamExactlyHere` (`fork_upstream_diff_test.go`) diffs
this tree against pristine upstream in the module cache and compares the
result with `FORK.patch` — the fork, in full. It FATALS when upstream is not
in the cache (`go mod download github.com/pion/turn/v5@v5.0.2`).
