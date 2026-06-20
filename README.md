# limitless-audit-chain

Limitless cross-substrate **audit-chain primitive** — the canonical Go
SDK behind **R-CROSS-INFRA-AUDIT-CHAIN-EMIT** (R187 candidate) and the
"shared library" leg of **R186 R-WORKSPACE-CRATE-COHORT-INTEGRATION-PATTERN**.

Zero external dependencies. Pure Go stdlib (Go 1.22+).

## What this is

A **sequence of signed receipts**, where each receipt commits to:

```
prev_receipt_hash || payload_hash || signer_id || timestamp
```

Verification walks bottom-up (genesis → tip), recomputing each
prev-hash and re-checking each signature. Tampering with any receipt
in the middle of the chain breaks either:

- The **signature** on that receipt (if the payload was edited), OR
- The **prev-hash** on the next receipt (if the receipt was substituted).

The chain is therefore **tamper-evident as a composite** even though
each individual receipt is independently signed by a different
emitter.

## Why this is its own SDK (extraction #8)

The audit-chain primitive originated in the I20 infra-marathon as a
demo of the five-step pipeline
`delve → grounded → recall → echo → parallax`. **It generalises beyond
that single pipeline.** Any cross-infra OR cross-flagship handoff can
use this:

- A single flagship signing successive emissions to its own audit
  ledger (`examples/single_consumer`).
- Two infra services exchanging a handoff payload (`examples/cross_infra`).
- A DSAR receipt chain across an Article-9 cohort.
- The original five-step ai-pipeline trust chain.

By extracting this primitive to its own SDK, the cohort gets **one
canonical implementation** that any substrate consumer can adopt —
no per-consumer re-port, no in-tree fork, no transitive trust on a
flagship's `internal/chain` package.

## Cross-substrate SDK family (this is #8)

| # | SDK                       | Substrate           |
|---|---------------------------|---------------------|
| 1 | `limitless-beam-otp`      | BEAM (Erlang/Elixir/Gleam) |
| 2 | `limitless-c-crypto`      | C / C++             |
| 3 | `limitless-rs`            | Rust                |
| 4 | `limitless-jvm`           | JVM (Kotlin/Java/Scala) |
| 5 | `limitless-ts`            | TypeScript          |
| 6 | `limitless-py`            | Python              |
| 7 | `limitless-proto`         | Protocol Buffer wire contracts |
| **8** | **`limitless-audit-chain`** | **Go canonical (this repo)** |

Future per-substrate ports will land their own audit-chain modules
whose canonical-bytes encoding is **byte-identical** to this Go
implementation. KAT-1 anchor (`239a7d0d…`) is the cross-substrate pin.

## Quickstart

```go
package main

import (
    "crypto/sha256"
    "fmt"
    "time"

    chain "github.com/davly/limitless-audit-chain/pkg/chain"
)

func main() {
    corpusSHA := sha256.Sum256([]byte("my-corpus"))
    key := []byte("my-hmac-key")

    c := chain.NewChain()
    c.RequireSigners = []chain.SignerID{"delve", "grounded", "recall"}

    signer := &chain.MirrorMarkSigner{CorpusSHA: corpusSHA, Key: key}
    t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

    _, _ = c.AppendSigned(signer, "delve",    []byte(`{"step":1}`), t0)
    _, _ = c.AppendSigned(signer, "grounded", []byte(`{"step":2}`), t0.Add(time.Second))
    _, _ = c.AppendSigned(signer, "recall",   []byte(`{"step":3}`), t0.Add(2*time.Second))

    if err := c.Verify(chain.MirrorMarkVerifier(corpusSHA, key)); err != nil {
        panic(err)
    }
    wire, _ := c.Export()
    fmt.Println(string(wire))
}
```

## R174 5-of-5 cohort pack

This SDK ships the cohort 5-pack from inception (per the R174
canonical reference template from `davly/conjure`):

| Pillar | Surface |
|--------|---------|
| **mirrormark** (L43) | `MirrorMarkSigner` + `MirrorMarkVerifier` + 4 constants + 4 sentinel errors |
| **kat** (R151)       | `KAT1HMACSHA256Hex` + `KAT1PublishedMark` + `AssertKAT1Parity()` + chain-level golden `BuildGoldenChainV1()` / `GoldenChainV1Signers` (frozen `testdata/golden_chain_v1{,.compact}.json`) |
| **honest** (R143)    | `LoudOnce` with `TryFire` / `HasFired` (atomic CAS) |
| **legal** (R166)     | `LiabilityFooter` + `ReviewedByCounsel` (false) + `LibraryRecommendsHostActs` |
| **manifest**         | `Manifest()` returning self-description with name + version + KAT-1 commitment |

All five pillars live in `pkg/chain` — substrate-native idiom (R157)
favors one-file-many-types in Go, over the per-pillar-directory
shape used in Rust / TS / Py.

## CLI

```bash
audit-chain verify   <chain.json>   # structural + KAT-1 self-check; exit 1 on fail
audit-chain inspect  <chain.json>   # human-readable chain dump
audit-chain manifest                # print SDK self-description
audit-chain kat1                    # print KAT-1 anchor + parity check
```

Pass `-` as the path to read JSON from stdin.

The CLI's `verify` is **structural-only** — it does not have the
substrate keys (corpus SHA + HMAC key for Mirror-Mark, or the public
key for ed25519/secp256k1). Production code wires
`chain.MirrorMarkVerifier(...)` directly in the consuming binary.

## R151 KAT-1 anchor (cross-substrate pin)

```
239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

Reproduce via OpenSSL on any UNIX:

```sh
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' $(seq 1 32) >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# -> HMAC-SHA256(stdin)= 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

Or via this SDK's test:

```sh
go test ./pkg/chain -run TestAssertKAT1Parity_Ok
```

Or the CLI:

```sh
audit-chain kat1
```

## Examples

```sh
# Three-hop cross-infra chain (delve → grounded → recall):
go run ./examples/cross_infra > /tmp/chain.json
audit-chain inspect /tmp/chain.json
audit-chain verify  /tmp/chain.json

# Single-flagship audit ledger (5 emissions):
go run ./examples/single_consumer > /tmp/ledger.json
audit-chain inspect /tmp/ledger.json
```

## File index

```
pkg/chain/
  receipt.go     ~250 LoC   Receipt + CanonicalBytes + Hash + ValidateReceiptShape
  chain.go       ~250 LoC   Chain type + Append + AppendSigned + Export + Import
  verify.go      ~190 LoC   VerifierFunc + Signer + MirrorMarkSigner/Verifier + sentinel errors
  cohort.go      ~200 LoC   R174 5-of-5 cohort pack (kat + honest + legal + manifest pillars)

cmd/audit-chain/
  main.go        ~180 LoC   CLI: verify / inspect / manifest / kat1

examples/
  cross_infra/main.go        ~100 LoC   3-hop cross-infra demo
  single_consumer/main.go    ~90  LoC   single-flagship audit ledger demo

pkg/chain/*_test.go         67 tests   (well above the 40-test minimum)
```

## R-rule lineage

- **R-CROSS-INFRA-AUDIT-CHAIN-EMIT** (R187 candidate) — this SDK is the
  CANONICAL LIBRARY backing the rule, saturating the "shared library"
  leg of R186.
- **R186 R-WORKSPACE-CRATE-COHORT-INTEGRATION-PATTERN** — extracted
  cross-substrate SDK (extraction #8 in the family).
- **R151 KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN** — KAT-1 hex
  literal byte-identical to ~30 substrate ports across the cohort.
- **R145.B SIBLING-NOT-STACKED** — this SDK lives in its own repo;
  per-consumer migrations land on their own additive branches.
- **R145.C FIREWALL-TEST-DISCIPLINE** — `TestKAT1_HMACSHA256HexPinned`,
  `TestKAT1_PublishedMarkPinned`, `TestKAT1_CanonicalInputShape`,
  `TestAssertKAT1Parity_Ok` pin the wire-format constants.
- **R143 LOUD-ONCE-WARNING-FLAG** — `LoudOnce` (atomic CAS gate) per
  substrate-native idiom in Go.
- **R166 LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE** —
  `LiabilityFooter` + `ReviewedByCounsel` honest-default sentinels.
- **R157 SUBSTRATE-NATIVE-IDIOM-OVER-LITERAL-TRANSLATION** — Go-idiom
  one-file-per-package vs the Rust/TS module-per-pillar shape.
- **R174 R-COHORT-5-OF-5-MATURITY-FROM-INCEPTION** — this SDK ships
  the 5-pack from commit #1, not retrofit.
- **L43 Mirror-Mark v1** — wire format is byte-identical to
  foundation/pkg/mirrormark and every cohort substrate port.

## What this is NOT

- **A production cryptographic library.** The Mirror-Mark verify uses
  `hmac.Equal` (constant-time) for the HMAC compare, but other paths
  (base64 decode, length checks, prefix compare) are NOT constant-time.
  No zeroize-on-drop, no FIPS validation. Adequate for the verdict-
  producer threat model the cohort serves.
- **A signature-substrate dispatcher.** The chain layer is signer-
  agnostic — it takes a `VerifierFunc` and calls it per receipt. The
  cohort SHIPS a Mirror-Mark verifier; consumers using ed25519 /
  secp256k1 / RSA implement their own `Signer` + `VerifierFunc`.
- **A migration of existing in-tree audit-chain forks.** Each
  consumer flagship that currently carries an internal `chain.go`
  (e.g. `limitless-audit-chain-demo`, `casino/handlers_dsar_receipt`)
  migrates on its own R145.B SIBLING-NOT-STACKED branch.

## License

Apache-2.0 — same as the rest of the davly cohort.
