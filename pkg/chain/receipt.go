// Package chain is the cohort-canonical audit-chain primitive — the
// load-bearing library behind R-CROSS-INFRA-AUDIT-CHAIN-EMIT and the
// "shared library" leg of R186 R-WORKSPACE-CRATE-COHORT-INTEGRATION-
// PATTERN.
//
// # The audit-chain primitive
//
// An audit chain is a strictly-ordered sequence of signed receipts
// where each receipt commits to the SHA-256 hash of its predecessor's
// canonical bytes. The cohort-canonical receipt commits to:
//
//	prev_receipt_hash || payload_hash || signer_id || timestamp
//
// Verification walks bottom-up (genesis → tip), recomputing each
// prev_receipt_hash and re-checking each signature; the chain is
// rejected if ANY link fails.
//
// # Why this is its own SDK (SDK extraction #8)
//
// The primitive generalises beyond the I20 demo's
// delve→grounded→recall→echo→parallax pipeline. ANY cross-infra OR
// cross-flagship handoff that needs tamper-evident provenance can use
// it. Examples:
//
//   - Single flagship signing successive emissions to its own audit
//     ledger (single-consumer use; see examples/single_consumer).
//   - Two infra services exchanging a handoff payload (cross-infra
//     use; see examples/cross_infra).
//   - DSAR receipt chain across an Article-9 cohort.
//   - Five-step ai-pipeline trust chain (I20's original case).
//
// By extracting this primitive to its own SDK, the cohort gets ONE
// canonical implementation that any substrate consumer can adopt — no
// per-consumer re-port, no in-tree fork, no transitive trust on a
// flagship's `internal/chain` package.
//
// # Substrate purity
//
// Pure Go stdlib. Zero external dependencies. Verifier is pluggable
// (the chain layer enforces structure; the caller plugs in the
// signature verifier for the substrate it consumes — Mirror-Mark
// HMAC, ed25519, RSA, secp256k1, etc.).
//
// # Cohort siblings
//
// This is SDK extraction #8 across the cross-substrate SDK family:
//
//	1. limitless-beam-otp   — BEAM (Erlang/Elixir/Gleam)
//	2. limitless-c-crypto   — C / C++
//	3. limitless-rs         — Rust
//	4. limitless-jvm        — JVM (Kotlin/Java/Scala)
//	5. limitless-ts         — TypeScript
//	6. limitless-py         — Python
//	7. limitless-proto      — Protocol Buffer wire contracts
//	8. limitless-audit-chain — THIS package (Go canonical)
//
// Future per-substrate ports (Rust / TS / Py / JVM) will land their
// own audit-chain modules whose canonical-bytes encoding is byte-
// identical to this package's output.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SignerID identifies who signed a receipt. Unlike the I20 demo (which
// hard-coded a closed-set of five signers), the SDK is open: any
// caller-defined string is accepted at the chain layer. Closed-set
// enforcement is an OPT-IN policy via Chain.RequireSigners (see
// chain.go), so an infra-only deployment can lock to the five-step
// pipeline while a single-consumer audit ledger can use one signer.
type SignerID string

// String returns the SignerID as a plain string (for fmt + JSON).
func (s SignerID) String() string { return string(s) }

// GenesisPrevHash is the 64-character sentinel used as the
// PrevReceiptHash of a chain's first receipt. Chosen distinct from any
// real SHA-256 output AND grep-discoverable in audit logs ("0"×64).
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// PayloadHashLen is the hex-encoded length of a SHA-256 payload hash
// (64 chars). Exposed as a constant so callers can validate inputs
// without importing crypto/sha256.
const PayloadHashLen = 2 * sha256.Size

// PrevHashLen is the hex-encoded length of a prev-receipt hash —
// identical to PayloadHashLen but named separately so callers reading
// chain code can distinguish the two semantic uses at the call site.
const PrevHashLen = 2 * sha256.Size

// Receipt is a single signed step in an audit chain.
//
// Wire format (sorted-key, newline-delimited UTF-8 — byte-identical
// to flagships/limitless-audit-chain-demo/internal/chain.Receipt and
// to every cohort substrate port of this SDK):
//
//	payload_hash: <hex SHA-256 of emitter's payload bytes>
//	prev_receipt_hash: <hex SHA-256 of preceding receipt's canonical bytes, or 64-char "0" string for genesis>
//	signer_id: <caller-defined string; closed-set enforcement is opt-in via RequireSigners>
//	timestamp: <RFC3339 UTC>
//
// The Signature field is computed OVER the canonical bytes above by
// the caller's signing primitive (Mirror-Mark HMAC-SHA256 today, but
// any deterministic signature scheme works). The chain Verify
// dispatches every receipt's signature to a caller-supplied verifier;
// it does NOT itself perform substrate-level signature verification.
//
// All fields are public to allow callers to JSON-marshal receipts
// for transport / Export / archival without an intermediate DTO.
type Receipt struct {
	// PrevReceiptHash is the hex-encoded SHA-256 over the canonical
	// bytes of the immediately-preceding Receipt in the chain.
	//
	// For the genesis receipt (no predecessor), this is the
	// 64-character GenesisPrevHash sentinel.
	PrevReceiptHash string `json:"prev_receipt_hash"`

	// PayloadHash is the hex-encoded SHA-256 over the caller's
	// domain-specific payload bytes (e.g. a schema-card, a citation,
	// a cache entry, a DSAR row, an emission record).
	//
	// The chain layer does NOT inspect the payload itself — it only
	// commits to the payload's hash. The caller is responsible for
	// binding the payload bytes back to the hash on the verify side.
	PayloadHash string `json:"payload_hash"`

	// SignerID identifies who signed this receipt. Any non-empty
	// string is structurally valid; closed-set enforcement is opt-in
	// per chain via Chain.RequireSigners.
	SignerID SignerID `json:"signer_id"`

	// Timestamp is the UTC RFC3339 time at which the receipt was
	// signed.
	Timestamp time.Time `json:"timestamp"`

	// Signature is the emitter's signature over the canonical bytes
	// of (PrevReceiptHash, PayloadHash, SignerID, Timestamp).
	// Opaque to the chain layer; verified via the caller-supplied
	// VerifierFunc passed to Chain.Verify.
	Signature string `json:"signature"`
}

// CanonicalBytes returns the deterministic, sort-stable, newline-
// delimited UTF-8 representation of the receipt's signed fields.
//
// The signer hashes / signs OVER these bytes. The verifier re-derives
// these bytes from the stored Receipt and feeds them to the signature
// verifier. Bit-equal across cohort substrate ports of this SDK.
//
// Field ordering is alphabetical-stable:
//
//	payload_hash:      ...
//	prev_receipt_hash: ...
//	signer_id:         ...
//	timestamp:         ...
//
// Trailing newline after each field. No leading newline. No BOM.
func (r Receipt) CanonicalBytes() []byte {
	var b strings.Builder
	b.Grow(64 + 64 + 64 + 32 + 64) // rough capacity hint
	fmt.Fprintf(&b, "payload_hash: %s\n", r.PayloadHash)
	fmt.Fprintf(&b, "prev_receipt_hash: %s\n", r.PrevReceiptHash)
	fmt.Fprintf(&b, "signer_id: %s\n", string(r.SignerID))
	fmt.Fprintf(&b, "timestamp: %s\n", r.Timestamp.UTC().Format(time.RFC3339))
	return []byte(b.String())
}

// Hash returns the hex-encoded SHA-256 of the receipt's canonical
// bytes. This is the value the NEXT receipt in the chain stores in
// its PrevReceiptHash field.
//
// Deterministic: identical Receipt → identical Hash across all
// substrate ports of this SDK.
func (r Receipt) Hash() string {
	sum := sha256.Sum256(r.CanonicalBytes())
	return hex.EncodeToString(sum[:])
}

// IsGenesis returns true when r is the first receipt in a chain
// (PrevReceiptHash = GenesisPrevHash).
func (r Receipt) IsGenesis() bool {
	return r.PrevReceiptHash == GenesisPrevHash
}

// HashPayload is a convenience for callers who hold raw payload bytes
// and want to derive the PayloadHash field. Pure SHA-256 hex.
//
// Exposed so a caller building a Receipt does not need to import
// crypto/sha256 directly — the SDK is the canonical place to derive
// payload hashes for chain receipts.
func HashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// ValidateReceiptShape performs structural validation on a single
// receipt WITHOUT walking the chain. Returns nil if the receipt is
// shape-valid (fields populated + hex lengths correct + signer non-
// empty + signature non-empty); a typed sentinel error otherwise.
//
// Useful for callers that build receipts incrementally (e.g. a CLI
// REPL) and want immediate feedback before appending to a chain.
func ValidateReceiptShape(r Receipt) error {
	if len(r.PrevReceiptHash) != PrevHashLen {
		return fmt.Errorf("%w: prev_receipt_hash length=%d, expected %d",
			ErrShapePrevHashLen, len(r.PrevReceiptHash), PrevHashLen)
	}
	if !isHex(r.PrevReceiptHash) {
		return ErrShapePrevHashNotHex
	}
	if len(r.PayloadHash) != PayloadHashLen {
		return fmt.Errorf("%w: payload_hash length=%d, expected %d",
			ErrShapePayloadHashLen, len(r.PayloadHash), PayloadHashLen)
	}
	if !isHex(r.PayloadHash) {
		return ErrShapePayloadHashNotHex
	}
	if r.SignerID == "" {
		return ErrShapeEmptySigner
	}
	if signerIDHasControlChars(r.SignerID) {
		return ErrSignerIDControlChar
	}
	if r.Timestamp.IsZero() {
		return ErrShapeZeroTimestamp
	}
	if r.Signature == "" {
		return ErrShapeEmptySignature
	}
	return nil
}

// signerIDHasControlChars reports whether s contains any ASCII control
// character (byte < 0x20: newline, carriage-return, tab, NUL, etc.).
//
// SignerID is serialised into the signed canonical bytes with an in-band
// newline+colon delimiter (see CanonicalBytes). A control character —
// especially a newline — in a signer_id would inject extra signed lines
// (e.g. a forged `timestamp:` value) into the canonical form, producing
// an ambiguous duplicate-field signed receipt and breaking cross-
// substrate byte-identity. Rejecting such signer_ids at the trust
// boundaries (Verify, AppendSigned, ValidateReceiptShape) is the
// canonical-form input-validation guard.
//
// All legitimate signer_ids (e.g. "delve" and the five pipeline names)
// are printable ASCII / UTF-8 with no control chars, so this guard is
// byte-identity-preserving for every real signer.
func signerIDHasControlChars(s SignerID) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return true
		}
	}
	return false
}

// isHex returns true iff s is composed entirely of lowercase hex digits.
// The cohort canonical form is lowercase (encoding/hex.EncodeToString).
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ----- Shape errors (Validate ReceiptShape) -----

// ErrShapePrevHashLen — prev_receipt_hash has wrong length.
var ErrShapePrevHashLen = errors.New("receipt: prev_receipt_hash wrong length")

// ErrShapePrevHashNotHex — prev_receipt_hash contains non-hex chars.
var ErrShapePrevHashNotHex = errors.New("receipt: prev_receipt_hash not lowercase hex")

// ErrShapePayloadHashLen — payload_hash has wrong length.
var ErrShapePayloadHashLen = errors.New("receipt: payload_hash wrong length")

// ErrShapePayloadHashNotHex — payload_hash contains non-hex chars.
var ErrShapePayloadHashNotHex = errors.New("receipt: payload_hash not lowercase hex")

// ErrShapeEmptySigner — signer_id is the empty string.
var ErrShapeEmptySigner = errors.New("receipt: empty signer_id")

// ErrSignerIDControlChar — signer_id contains an ASCII control character
// (newline / carriage-return / other byte < 0x20) which would inject
// extra lines into the signed canonical bytes (canonical-bytes
// injection). Rejected at every trust boundary.
var ErrSignerIDControlChar = errors.New("chain: signer_id contains control characters (canonical-bytes injection)")

// ErrShapeZeroTimestamp — timestamp is the zero value.
var ErrShapeZeroTimestamp = errors.New("receipt: zero timestamp")

// ErrShapeEmptySignature — signature is the empty string.
var ErrShapeEmptySignature = errors.New("receipt: empty signature")
