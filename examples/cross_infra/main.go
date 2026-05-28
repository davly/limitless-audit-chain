// Cross-infra example: minimal 3-step chain demonstrating
// R-CROSS-INFRA-AUDIT-CHAIN-EMIT in the library-as-SDK form.
//
// Run:
//
//	go run ./examples/cross_infra
//
// Outputs a JSON chain that the audit-chain CLI can verify:
//
//	go run ./examples/cross_infra > /tmp/chain.json
//	audit-chain inspect /tmp/chain.json
//	audit-chain verify  /tmp/chain.json
//
// This mirrors the I20 demo's five-step pipeline at smaller scale —
// 3 steps instead of 5, to make the example readable in one screen.
//
// Storyline: a Limitless request travels through THREE infra hops
// (delve → grounded → recall), each signing a receipt before handing
// off to the next. The chain of receipts is the audit trail.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	chain "github.com/davly/limitless-audit-chain/pkg/chain"
)

func main() {
	// (1) Shared cohort substrate: corpus SHA + HMAC key. In
	// production each infra would source these via its own
	// MarkerFromEnv constructor; the example hard-codes them.
	corpusSHA := sha256.Sum256([]byte("example.cross_infra.corpus"))
	key := []byte("EXAMPLE_DEMO_KEY_DO_NOT_USE_IN_PRODUCTION")

	// (2) Build the chain. RequireSigners closes the chain to the
	// three known infra signers — any rogue signer (e.g. a tampered
	// payload spoofing "echo") is rejected at Verify time.
	c := chain.NewChain()
	c.RequireSigners = []chain.SignerID{"delve", "grounded", "recall"}
	c.Metadata = map[string]string{
		"cohort":  "limitless-audit-chain-example",
		"purpose": "cross-infra 3-hop demo",
		"version": chain.SDKVersion,
	}

	// (3) Three infra hops, each with its own MirrorMarkSigner. In
	// production each infra would own its own (corpus, key) pair,
	// or share one via Nexus key-management. The example uses one
	// signer for brevity — substituting per-infra signers is a
	// straightforward extension.
	signer := &chain.MirrorMarkSigner{CorpusSHA: corpusSHA, Key: key}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	// Step 1: delve emits a schema-card receipt.
	r0, err := c.AppendSigned(signer, "delve",
		[]byte(`{"schema_card":"users","columns":17}`), t0)
	if err != nil {
		fail(err)
	}

	// Step 2: grounded emits a citation receipt linking back to delve.
	r1, err := c.AppendSigned(signer, "grounded",
		[]byte(`{"citation":"users.email","source_sha":"abcd1234"}`), t0.Add(time.Second))
	if err != nil {
		fail(err)
	}

	// Step 3: recall emits a cache receipt linking back to grounded.
	r2, err := c.AppendSigned(signer, "recall",
		[]byte(`{"cache_key":"users.email","ttl":300}`), t0.Add(2*time.Second))
	if err != nil {
		fail(err)
	}

	// (4) Verify locally with the canonical Mirror-Mark verifier.
	if err := c.Verify(chain.MirrorMarkVerifier(corpusSHA, key)); err != nil {
		fail(err)
	}

	// (5) Print the chain as JSON to stdout.
	wire, err := c.Export()
	if err != nil {
		fail(err)
	}
	fmt.Fprintln(os.Stdout, string(wire))

	// (6) Print a stderr summary so operators see what just signed.
	fmt.Fprintln(os.Stderr, "Chain verified locally. Receipts:")
	for i, r := range []chain.Receipt{r0, r1, r2} {
		fmt.Fprintf(os.Stderr, "  [%d] %-9s ts=%s prev=%s…\n",
			i, r.SignerID, r.Timestamp.UTC().Format("15:04:05Z"), r.PrevReceiptHash[:12])
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "example/cross_infra: %v\n", err)
	os.Exit(1)
}
