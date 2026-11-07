# Traceback maintenance branch

`codex/traceback` starts at stable 8.0.0, commit
`6f85481b63a929e0bcf88459bf9c73057992eebe` (2026-11-05).
The fork's stable/beta/develop branches remain upstream mirrors. No upstream PR is part of this work.
Only the MIT proxy core, its API declarations and regression/build support are maintained here.
Traceback consumes an explicit gitlink, never a moving branch or a repacked NuGet binary.

## Upstream fixes carried after stable

| Source commit | Selection |
| --- | --- |
| `606f23955a2e347b34f619ed6085e28176e7f792` | Core listener bind conflicts/cleanup, ProxyListenException and PublicAPI; no CLI, Gateway or Inspector changes |
| `f0854261903e7a3b7e9b32bb031ea1bec92054d7` | Relayed HTTP/2 MAX_FRAME_SIZE agrees with actual parser limit |
| `92356e3deb8a51664437615bf00f6280e5bc9014` | Header-list decode limits agree with SETTINGS; stable's existing protocol paths only |

## Old 7.0.4 patch disposition

| Behavior | 8.0.0 decision |
| --- | --- |
| Generic certificate, DNS SNI, CONNECT fallback | Port per-connection selection; retain speculative CONNECT-time generation and cache |
| Unknown-length H2 request body | Already represented by OriginalHasBody/HEADERS END_STREAM; no duplicate state |
| H2 response larger than 4 MiB | Retain upstream response pipe and receive-credit design; exercise with streaming tests |
| Observed H2 DATA overtakes HEADERS | Retain upstream queued writer/order/flow-control design |
| H1/H2 bridge request/response observation and final notification | Port missing paths with ObservedBodyWriteStream and existing body events |
| Fixed-length short read, chunked terminator/trailer EOF, cancellation | Port strict failure semantics and cancellable drains |
| RST after response headers; H1 close-delimited RST versus FIN | Port transport error preservation and abort only affected H1 socket / H2 stream |
| Last 8,193 bytes before interruption | Forward every successful read immediately instead of filling an aggregate buffer |
| Small H2 origin response inline optimization | Disable inline buffering for observed streaming responses; reject short buffered reads instead of resizing to success |
| H2 to H1 request queue overflow under slow origin | Return stream receive credit after origin consumption; bound outstanding bytes by the advertised window without blocking other streams |
| Explicit whole-body read budgets | Enforce limits for inline/already buffered and streamed bridge bodies, including decompression |
| H1 bodyless response notification | Emit one final empty body observation, matching the H2 bridge contract |
| Late H2 response trailers | Copy trailers after draining DATA and before the H1 chunked terminator |

Tests use loopback origins and temporary CAs. They do not install trust anchors or change system proxy settings.
The suppression path presents a leaf directly for self-signed temporary CAs; it does not invoke a certificate-store scrubber.
Upstream's broad MSTest store-cleanup fixture is **not** safe for a developer's personal certificate stores.
Use the standalone project, or the selected upstream tests with `-p:IsTestHost=false` and
`TITANIUM_SKIP_ROOT_STORE_UI=1` as shown in `.github/workflows/traceback.yml`. Do not run the unfiltered upstream suites on a personal machine.
The existing upstream integration project builds additional test dependencies; the new regression project and the platform reference only core/Abstractions.

## Validation and upgrades

Untouched stable characterization: 6 passed / 9 failed in the corrected standalone fixture (15 cases);
platform proxy/lifecycle characterization: 23 passed / 21 failed (44 cases).
Final local verification: 49/49 standalone regressions, 6/6 selected upstream core units, and 17/17 selected upstream HTTP/2 wire tests.
These are local protocol tests, not production UGC/CDN acceptance. Platform evidence and final results live in
`docs/agents/titanium-fork-maintenance.md` in the consuming repository.

Merge future stable releases into this maintenance branch without rewriting published history.
Re-evaluate each row above, rerun the same core and platform protocol checks, push the tested fork commit,
then explicitly update the platform gitlink. Never silently fall back to a historical package.
No new H3/CONNECT-UDP/WebTransport feature is adopted or accepted here; existing stable paths touched by a shared
limit or cancellation-token change are not claims of H3 runtime coverage.
