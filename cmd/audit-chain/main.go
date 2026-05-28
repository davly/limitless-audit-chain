// Command audit-chain is the CLI wrapper around the limitless-audit-
// chain SDK. Two subcommands today:
//
//	audit-chain verify  <chain.json>     # structural + canonical KAT-1 verify
//	audit-chain inspect <chain.json>     # human-readable chain dump
//
// Both subcommands read the chain JSON from disk (or stdin if path is
// "-"). The verify subcommand exits 0 on success, 1 on any failure;
// the inspect subcommand is read-only and exits 0 unless the JSON is
// fundamentally malformed.
//
// CLI is intentionally minimal — the bulk of audit-chain functionality
// lives in pkg/chain. Production deployments wrap the SDK directly;
// the CLI is for operators / regulators verifying a chain off-host.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	chain "github.com/davly/limitless-audit-chain/pkg/chain"
)

func main() {
	flag.Usage = printUsage
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "verify: missing <chain.json> argument")
			os.Exit(2)
		}
		if err := cmdVerify(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "verify: %v\n", err)
			os.Exit(1)
		}
	case "inspect":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "inspect: missing <chain.json> argument")
			os.Exit(2)
		}
		if err := cmdInspect(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "inspect: %v\n", err)
			os.Exit(1)
		}
	case "manifest":
		printManifest()
	case "kat1":
		printKAT1()
	default:
		fmt.Fprintf(os.Stderr, "audit-chain: unknown subcommand %q\n\n", args[0])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "audit-chain — Limitless cross-infra audit-chain CLI")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "USAGE")
	fmt.Fprintln(os.Stderr, "  audit-chain verify   <chain.json>   # structural + KAT-1 verify; exit 1 on failure")
	fmt.Fprintln(os.Stderr, "  audit-chain inspect  <chain.json>   # human-readable chain dump")
	fmt.Fprintln(os.Stderr, "  audit-chain manifest                # print SDK self-description (JSON)")
	fmt.Fprintln(os.Stderr, "  audit-chain kat1                    # print KAT-1 anchor + cohort-canonical mark")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Pass '-' as the path to read JSON from stdin.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Liability footer:")
	fmt.Fprintln(os.Stderr, "  "+chain.LiabilityFooter)
}

func readChainFile(path string) (*chain.Chain, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	c, err := chain.Import(data)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func cmdVerify(path string) error {
	c, err := readChainFile(path)
	if err != nil {
		return err
	}
	if err := chain.AssertKAT1Parity(); err != nil {
		return fmt.Errorf("KAT-1 self-check failed: %w", err)
	}
	// Structural-only verify (no signer-substrate plug-in available
	// from a JSON file — the caller has not provided keys). Print a
	// loud advisory so operators know signature verification was
	// NOT performed.
	if err := c.VerifyStructural(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "STRUCTURAL VERIFY: PASS")
	fmt.Fprintf(os.Stdout, "  chain length: %d\n", c.Len())
	fmt.Fprintf(os.Stdout, "  KAT-1 anchor: %s\n", chain.KAT1HMACSHA256Hex)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "ADVISORY: structural-only verify. Signature verification requires")
	fmt.Fprintln(os.Stdout, "  the substrate keys (corpus SHA + HMAC key for Mirror-Mark, or")
	fmt.Fprintln(os.Stdout, "  the public key for ed25519/secp256k1). Wire those in your own")
	fmt.Fprintln(os.Stdout, "  binary via chain.MirrorMarkVerifier / custom VerifierFunc.")
	return nil
}

func cmdInspect(path string) error {
	c, err := readChainFile(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "AUDIT CHAIN INSPECT")
	fmt.Fprintf(os.Stdout, "  length: %d\n", c.Len())
	if len(c.RequireSigners) > 0 {
		fmt.Fprintf(os.Stdout, "  require_signers: %s\n",
			strings.Join(signersAsStrings(c.RequireSigners), ", "))
	} else {
		fmt.Fprintln(os.Stdout, "  require_signers: (open — any signer accepted)")
	}
	if len(c.Metadata) > 0 {
		fmt.Fprintln(os.Stdout, "  metadata:")
		for k, v := range c.Metadata {
			fmt.Fprintf(os.Stdout, "    %s: %s\n", k, v)
		}
	}
	fmt.Fprintln(os.Stdout, "  receipts:")
	for i, r := range c.Receipts {
		fmt.Fprintf(os.Stdout, "    [%d] signer=%s ts=%s\n",
			i, r.SignerID, r.Timestamp.UTC().Format("2006-01-02T15:04:05Z"))
		fmt.Fprintf(os.Stdout, "        prev_hash:    %s\n", short(r.PrevReceiptHash))
		fmt.Fprintf(os.Stdout, "        payload_hash: %s\n", short(r.PayloadHash))
		fmt.Fprintf(os.Stdout, "        signature:    %s\n", short(r.Signature))
	}
	// Structural pass advisory.
	if err := c.VerifyStructural(); err != nil {
		fmt.Fprintf(os.Stdout, "\nSTRUCTURAL VERIFY: FAIL — %v\n", err)
		return nil
	}
	fmt.Fprintln(os.Stdout, "\nSTRUCTURAL VERIFY: PASS")
	return nil
}

func printManifest() {
	m := chain.Manifest()
	fmt.Fprintf(os.Stdout, "name:        %s\n", m.Name)
	fmt.Fprintf(os.Stdout, "version:     %s\n", m.Version)
	fmt.Fprintf(os.Stdout, "kat1_digest: %s\n", m.KAT1Digest)
	fmt.Fprintf(os.Stdout, "wire_format: %s\n", m.WireFormat)
	fmt.Fprintf(os.Stdout, "description: %s\n", m.Description)
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "liability_footer:")
	fmt.Fprintln(os.Stdout, "  "+chain.LiabilityFooter)
}

func printKAT1() {
	in := chain.KAT1CanonicalInput()
	fmt.Fprintf(os.Stdout, "KAT-1 cohort invariant\n")
	fmt.Fprintf(os.Stdout, "  hmac_sha256_hex:  %s\n", chain.KAT1HMACSHA256Hex)
	fmt.Fprintf(os.Stdout, "  published_mark:   %s\n", chain.KAT1PublishedMark)
	fmt.Fprintf(os.Stdout, "  canonical_input:  %s (length=%d)\n", hex.EncodeToString(in), len(in))
	fmt.Fprintln(os.Stdout, "  canonical_key:    (empty)")
	if err := chain.AssertKAT1Parity(); err != nil {
		fmt.Fprintf(os.Stdout, "\nPARITY: FAIL — %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "\nPARITY: PASS (substrate matches cohort anchor)")
}

func signersAsStrings(ss []chain.SignerID) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}

func short(s string) string {
	if len(s) <= 18 {
		return s
	}
	return s[:8] + "…" + s[len(s)-8:]
}

// Ensure errors is referenced even if no shape errors caught here —
// future subcommands may need it.
var _ = errors.Is
