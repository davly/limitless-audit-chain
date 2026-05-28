// Single-consumer example: a flagship signs successive emissions
// into its own audit ledger.
//
// Run:
//
//	go run ./examples/single_consumer
//
// Demonstrates that the audit-chain primitive works at single-
// consumer scale (not just cross-infra). A regulator reading the
// resulting JSON chain can verify:
//
//   - Every emission was signed by THIS flagship and only this
//     flagship (RequireSigners closes the set to one).
//   - No emission was inserted between two others (prev-hash chain).
//   - No emission timestamp was rewound (timestamp monotonicity).
//
// Storyline: a DSAR-fulfilment flagship (e.g. Folio, Casino, Paradox)
// signs successive ledger rows as audit-chain receipts. The chain is
// the article-9 / R154.A DSAR audit trail.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	chain "github.com/davly/limitless-audit-chain/pkg/chain"
)

func main() {
	// Flagship-specific cohort substrate.
	corpusSHA := sha256.Sum256([]byte("example.single_consumer.flagship-x.corpus"))
	key := []byte("FLAGSHIP_X_EXAMPLE_KEY_DO_NOT_USE_IN_PRODUCTION")

	// Chain closed to ONE signer — this flagship's emission service.
	c := chain.NewChain()
	c.RequireSigners = []chain.SignerID{"flagship-x.emitter"}
	c.Metadata = map[string]string{
		"flagship":    "flagship-x",
		"audit_class": "dsar_article_9",
		"version":     chain.SDKVersion,
	}

	signer := &chain.MirrorMarkSigner{CorpusSHA: corpusSHA, Key: key}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	// Simulate five successive ledger emissions over five seconds.
	emissions := []struct {
		when    time.Time
		payload []byte
	}{
		{t0.Add(0 * time.Second), []byte(`{"dsar_event":"intake","subject":"u_42"}`)},
		{t0.Add(1 * time.Second), []byte(`{"dsar_event":"locate","store":"users.email"}`)},
		{t0.Add(2 * time.Second), []byte(`{"dsar_event":"export","format":"json"}`)},
		{t0.Add(3 * time.Second), []byte(`{"dsar_event":"delivery","channel":"portal"}`)},
		{t0.Add(4 * time.Second), []byte(`{"dsar_event":"complete","sla_seconds":4}`)},
	}

	for _, e := range emissions {
		if _, err := c.AppendSigned(signer, "flagship-x.emitter", e.payload, e.when); err != nil {
			fail(err)
		}
	}

	// Local Mirror-Mark verify (self-test before persisting).
	if err := c.Verify(chain.MirrorMarkVerifier(corpusSHA, key)); err != nil {
		fail(err)
	}

	// Wire format to stdout — this is what would land in the
	// flagship's audit ledger table / object store.
	wire, err := c.Export()
	if err != nil {
		fail(err)
	}
	fmt.Fprintln(os.Stdout, string(wire))

	// Stderr summary.
	fmt.Fprintln(os.Stderr, "Single-consumer audit chain verified locally.")
	fmt.Fprintf(os.Stderr, "  receipts:        %d\n", c.Len())
	fmt.Fprintf(os.Stderr, "  kat1_digest:     %s\n", chain.KAT1HMACSHA256Hex)
	fmt.Fprintf(os.Stderr, "  liability_note:  %s\n", chain.LibraryRecommendsHostActs)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "example/single_consumer: %v\n", err)
	os.Exit(1)
}
