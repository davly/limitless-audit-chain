# limitless-audit-chain — CONTEXT

## Scope (what this SDK is)

A **Go canonical** implementation of the cross-substrate audit-chain
primitive — a sequence of signed receipts where each receipt commits
to `(prev_receipt_hash || payload_hash || signer_id || timestamp)`,
and verification walks bottom-up to confirm prev-hash continuity +
signature validity.

Single package surface: `pkg/chain`, containing the four module
shapes (receipt / chain / verify / cohort) per the cohort R157
substrate-native idiom (in Go, one file per concern inside one
package — not the per-pillar-directory shape Rust/TS use).

## Audit-chain SDK extraction #8

This is the **eighth cross-substrate SDK extraction** in the davly /
Limitless ecosystem:

1. `limitless-beam-otp` — BEAM (Erlang/Elixir/Gleam)
2. `limitless-c-crypto` — C / C++
3. `limitless-rs` — Rust
4. `limitless-jvm` — JVM (Kotlin/Java/Scala)
5. `limitless-ts` — TypeScript
6. `limitless-py` — Python
7. `limitless-proto` — Protocol Buffer wire contracts
8. **`limitless-audit-chain`** — **Go canonical** (this repo)

## Generalisation thesis

The audit-chain primitive originated as the I20 infra-marathon demo
for the five-step pipeline `delve → grounded → recall → echo →
parallax`. The I20 demo's `internal/chain` package was rich but
locked to that single pipeline — its `SignerID` enum closed at five
members.

This SDK **generalises**:

- `SignerID` is an open type — any caller-defined string.
- `RequireSigners` is opt-in policy — empty means any non-empty
  signer is accepted; populated means closed-set enforcement.
- The bottom-up verifier is signer-agnostic — the caller plugs in a
  `VerifierFunc` that knows the substrate (Mirror-Mark HMAC for the
  cohort canonical, ed25519/secp256k1/RSA for off-cohort consumers).

The generalisation is what makes this an **SDK**, not a flagship-
internal package. ANY cross-infra or cross-flagship handoff can use
it.

## Substrate purity discipline

- **Zero external dependencies.** `go.mod` declares Go 1.22 and
  NOTHING else. Pure stdlib: `crypto/sha256`, `crypto/hmac`,
  `encoding/base64`, `encoding/hex`, `encoding/json`, `sync/atomic`,
  `time`, `strings`, `sort`, `errors`, `fmt`, `io`, `os`, `flag`.
- **No file IO at the library surface.** Library never reads disk or
  network. CLI reads from disk/stdin; library does not.
- **Go 1.22 minimum.** Uses `sync/atomic.Bool` (Go 1.19+) and
  `errors.Join` (Go 1.20+) and JSON struct-tag preservation. The
  cohort SDK family targets Go 1.22 to align with foundation/pkg.

## R174 5-of-5 cohort pack (FROM INCEPTION)

Per `davly/conjure` (the canonical R174 inception-first reference),
this SDK ships the five pillars at commit #1:

1. **mirrormark** (L43) — `MirrorMarkSigner` + `MirrorMarkVerifier` +
   4 wire-format constants + 4 sentinel errors. Byte-identical output
   to `foundation/pkg/mirrormark` and every cohort substrate port.
2. **kat** (R151) — `KAT1HMACSHA256Hex` (`239a7d0d…`) +
   `KAT1PublishedMark` (62-char canonical mark) +
   `AssertKAT1Parity()` (substrate self-check). Plus the **chain-level
   KAT**: `BuildGoldenChainV1()` / `GoldenChainV1Signers` deterministically
   construct a golden 3-receipt chain (delve→grounded→recall, KAT-1
   substrate) whose `Export()`/`ExportCompact()` bytes are frozen in
   `pkg/chain/testdata/golden_chain_v1{,.compact}.json` and pinned by
   `kat_chain_test.go`. This freezes the chain wire format before the
   first cross-substrate consumer port; a port that reproduces these
   bytes HAS demonstrated chain byte-parity (no parity claim is made
   until one does).
3. **honest** (R143) — `LoudOnce` with atomic CAS `TryFire` / `HasFired`.
4. **legal** (R166) — `LiabilityFooter` + `ReviewedByCounsel` (false)
   + `LibraryRecommendsHostActs`.
5. **manifest** — `Manifest()` returning self-description (name +
   version + KAT-1 commitment + wire format + description).

R145.C FIREWALL-TEST-DISCIPLINE pins (`TestKAT1_HMACSHA256HexPinned`,
`TestKAT1_PublishedMarkPinned`, `TestKAT1_CanonicalInputShape`,
`TestKAT1_CorpusSHAZero`, `TestAssertKAT1Parity_Ok`,
`TestMirrorMarkSigner_KAT1MatchesPublishedMark`) guarantee the SDK
cannot accidentally drift from the cohort cross-substrate anchor.

## Test surface

```
pkg/chain/receipt_test.go   17 tests   shape + canonical-bytes + hash
pkg/chain/chain_test.go     24 tests   structure + Verify + Export/Import + AppendSigned
pkg/chain/cohort_test.go    17 tests   R174 5-of-5 pillar assertions
pkg/chain/verify_test.go     9 tests   MirrorMark roundtrip + error wrap propagation
                            ──
                            67 tests   (well over the 40-test minimum)
```

All tests run with `go test ./pkg/chain`. The full SDK builds with
`go build ./...` on Go 1.22+.

## Cohort consumer migration spec

The first downstream consumer is **`limitless-audit-chain-demo`**
(the I20 flagship at `C:\limitless\flagships\limitless-audit-chain-
demo`). Migration replaces its `internal/chain` package with a thin
shim that re-exports from `github.com/davly/limitless-audit-chain/
pkg/chain`. The demo's hard-coded five-signer `SignerID` enum
migrates to `Chain.RequireSigners = []SignerID{...}` — a one-line
change at the chain-construction site.

Other consumer flagships with cross-infra audit-chain needs (casino's
`handlers_dsar_receipt`, paradox/spark's `dsar/handler`, abyss's
chain-logger) are candidate migrations on subsequent R145.B SIBLING-
NOT-STACKED branches.

The migrations are **OUT OF SCOPE for this initial commit** — this
library is the precondition, not the migration.

## Threat model

### What this SDK protects against

- Receipt-payload tampering (caught by signature mismatch).
- Receipt-substitution (caught by prev-hash mismatch on next receipt).
- Receipt re-ordering (caught by timestamp inversion).
- Replay (caught by prev-hash binding to a specific chain prefix).
- Unknown-signer injection under closed-set policy (caught by
  RequireSigners).

### What this SDK does NOT protect against

- Side-channel attacks on the HMAC verify path (only `hmac.Equal` is
  constant-time; base64 decode + length checks + prefix compare are
  NOT).
- Compromised signer keys (the SDK has no key-management surface —
  consumers wire that in their own MarkerFromEnv constructors).
- Compromised cohort corpus (the SDK trusts the corpus SHA supplied
  by the caller).
- Reproducibility of upstream payload bytes (the chain commits to
  payload HASHES; binding the hash back to bytes is the caller's
  responsibility).

## Build host availability

Go 1.22+ is required for build + test. Verified locally on Go 1.26.2
windows/amd64. The cohort precedent for deferred build (e.g.
`limitless-rs` deferring `cargo` to CI on hosts without a Rust
toolchain) is also available here, but since Go is the canonical
limitless substrate, the build always runs on the dev host.

## License

Apache-2.0 — same as the rest of the davly cohort.
