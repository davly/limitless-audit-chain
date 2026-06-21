package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Chain is an ordered sequence of Receipts forming a verifiable audit
// trail. Goroutine-safety: Chain is NOT goroutine-safe. Callers that
// share a Chain across goroutines MUST hold an external mutex.
//
// The zero-value Chain is a valid empty chain. NewChain is provided as
// a constructor for readability + future-proofing (so callers don't
// rely on struct-literal construction).
type Chain struct {
	// Receipts are the chain's receipts in append order. The genesis
	// receipt is Receipts[0]; the tip is Receipts[len-1].
	Receipts []Receipt `json:"receipts"`

	// RequireSigners, if non-empty, enables closed-set signer-id
	// enforcement during Verify. Receipts whose SignerID is not in
	// this set are rejected. Empty (the default) means any non-empty
	// SignerID is accepted — useful for single-consumer chains where
	// the signer set is unbounded.
	RequireSigners []SignerID `json:"require_signers,omitempty"`

	// Metadata is a caller-attached annotation map serialised
	// alongside the chain on Export. Opaque to the chain layer.
	// Typical keys: "cohort", "purpose", "version".
	Metadata map[string]string `json:"metadata,omitempty"`
}

// NewChain returns a new empty Chain. Equivalent to &Chain{} but more
// readable at call sites.
func NewChain() *Chain {
	return &Chain{}
}

// Len returns the chain length.
func (c *Chain) Len() int { return len(c.Receipts) }

// Tip returns the most-recently-appended receipt and ok=true; or the
// zero Receipt and ok=false if the chain is empty.
func (c *Chain) Tip() (Receipt, bool) {
	if len(c.Receipts) == 0 {
		return Receipt{}, false
	}
	return c.Receipts[len(c.Receipts)-1], true
}

// Genesis returns the first receipt and ok=true; or the zero Receipt
// and ok=false if the chain is empty.
func (c *Chain) Genesis() (Receipt, bool) {
	if len(c.Receipts) == 0 {
		return Receipt{}, false
	}
	return c.Receipts[0], true
}

// Append adds a pre-built Receipt to the chain. The caller is
// responsible for setting PrevReceiptHash correctly — Append does NOT
// compute it automatically.
//
// This preserves the cohort discipline that the SIGNER computes the
// prev-hash from the parent receipt visible to it at signing time
// (otherwise the chain layer would have to forge the signer's input,
// which violates the "chain is the verifier, not the builder"
// invariant — see chain_test.go::TestVerify_TamperingMiddleReceipt-
// BreaksChain in the I20 demo).
//
// For the common case of "build my own chain end-to-end", use Sign
// (signer.go) which DOES compute the prev-hash from the chain tip.
func (c *Chain) Append(r Receipt) {
	c.Receipts = append(c.Receipts, r)
}

// SignerSequence returns the signer IDs in append order — used by
// tests + CLI to assert pipeline order without exposing the full
// receipt bodies.
func (c *Chain) SignerSequence() []SignerID {
	out := make([]SignerID, 0, len(c.Receipts))
	for _, r := range c.Receipts {
		out = append(out, r.SignerID)
	}
	return out
}

// SortedReceiptsCopy returns a defensive copy of the chain's receipts
// sorted by Timestamp ascending. Used by audit-export surfaces that
// emit a canonical timeline view.
//
// The copy is defensive: mutations to the returned slice do not
// affect the chain's internal state.
func (c *Chain) SortedReceiptsCopy() []Receipt {
	out := make([]Receipt, len(c.Receipts))
	copy(out, c.Receipts)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out
}

// IsAllowedSigner reports whether s is permitted under this chain's
// RequireSigners policy. If RequireSigners is empty (default), all
// non-empty SignerIDs are allowed.
func (c *Chain) IsAllowedSigner(s SignerID) bool {
	if s == "" {
		return false
	}
	if len(c.RequireSigners) == 0 {
		return true
	}
	for _, allowed := range c.RequireSigners {
		if allowed == s {
			return true
		}
	}
	return false
}

// AppendSigned builds a new Receipt linked to the chain tip, signs it
// via the supplied Signer, and appends it. Returns the resulting
// Receipt.
//
// This is the convenience constructor for callers that own both ends
// of the chain (e.g. a single flagship signing its own emissions —
// see examples/single_consumer).
//
// Behavior:
//
//  1. prev_receipt_hash := chain.Tip().Hash()  (or GenesisPrevHash if empty)
//  2. payload_hash      := HashPayload(payload)
//  3. timestamp         := now() (UTC, RFC3339-rounded)
//  4. signature         := signer.Sign(canonical_bytes_so_far)
//  5. chain.Append(receipt)
//
// The Signer interface lives in signer.go so callers can plug in any
// substrate (Mirror-Mark HMAC, ed25519, secp256k1, RSA, ...) without
// importing crypto/* at this layer.
func (c *Chain) AppendSigned(
	signer Signer,
	signerID SignerID,
	payload []byte,
	now time.Time,
) (Receipt, error) {
	if signer == nil {
		return Receipt{}, ErrAppendNilSigner
	}
	if signerID == "" {
		return Receipt{}, ErrShapeEmptySigner
	}
	if !c.IsAllowedSigner(signerID) {
		return Receipt{}, fmt.Errorf("%w: signer=%q not in RequireSigners",
			ErrUnknownSigner, signerID)
	}

	var prevHash string
	if t, ok := c.Tip(); ok {
		prevHash = t.Hash()
	} else {
		prevHash = GenesisPrevHash
	}

	r := Receipt{
		PrevReceiptHash: prevHash,
		PayloadHash:     HashPayload(payload),
		SignerID:        signerID,
		Timestamp:       now.UTC().Truncate(time.Second),
	}
	sig, err := signer.Sign(r.CanonicalBytes())
	if err != nil {
		return Receipt{}, fmt.Errorf("chain: signer failed: %w", err)
	}
	r.Signature = sig
	c.Receipts = append(c.Receipts, r)
	return r, nil
}

// ErrAppendNilSigner — AppendSigned called with a nil Signer.
var ErrAppendNilSigner = errors.New("chain: AppendSigned called with nil Signer")

// ----- Export / Import -----

// Export serialises the chain to JSON bytes. Stable wire format —
// the cohort JSON encoding is defined as Go's encoding/json with
// sort-stable field order (which is struct-tag-order: receipts,
// require_signers, metadata).
//
// Receipts inside the chain serialise per Receipt's JSON tags
// (prev_receipt_hash / payload_hash / signer_id / timestamp /
// signature). Timestamps emit as RFC3339 via time.Time's JSON marshal.
//
// Export is deterministic for a given Chain value: running it twice
// returns byte-identical output.
func (c *Chain) Export() ([]byte, error) {
	// Use json.MarshalIndent so audit-chain JSON files are
	// human-readable on disk. The CLI's `audit-chain inspect`
	// subcommand depends on this readability.
	return json.MarshalIndent(c, "", "  ")
}

// ExportCompact is the no-whitespace variant of Export. Used by
// transport surfaces that need byte-tight wire encoding.
func (c *Chain) ExportCompact() ([]byte, error) {
	return json.Marshal(c)
}

// Import parses JSON-encoded bytes (per Export) back into a Chain.
// Returns a typed sentinel error on malformed input.
//
// Import does NOT call Verify — callers MUST call Chain.Verify after
// Import if they want to confirm chain integrity. This separation lets
// a caller load an untrusted chain, inspect its metadata, and decide
// whether to verify (e.g. a verifier might want to display the chain
// length to the operator before doing expensive signature work).
func Import(data []byte) (*Chain, error) {
	if len(data) == 0 {
		return nil, ErrImportEmpty
	}
	c := &Chain{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrImportMalformed, err)
	}
	return c, nil
}

// ErrImportEmpty — Import called with empty input.
var ErrImportEmpty = errors.New("chain: Import called with empty input")

// ErrImportMalformed — Import received non-JSON or shape-wrong JSON.
var ErrImportMalformed = errors.New("chain: malformed import data")

// ----- Verification errors -----
//
// Shared across chain.go + verify.go. Defined here so callers see one
// canonical sentinel list when grepping the package.

// ErrEmptyChain — Verify called on a zero-length chain.
var ErrEmptyChain = errors.New("chain: empty chain (nothing to verify)")

// ErrGenesisPrevHash — first receipt's PrevReceiptHash is not the
// canonical sentinel.
var ErrGenesisPrevHash = errors.New("chain: first receipt PrevReceiptHash must be the genesis sentinel")

// ErrPrevHashMismatch — non-genesis receipt's PrevReceiptHash does
// not equal the predecessor's computed Hash.
var ErrPrevHashMismatch = errors.New("chain: prev_receipt_hash does not match predecessor's Hash()")

// ErrUnknownSigner — receipt's SignerID is not in the configured
// RequireSigners set.
var ErrUnknownSigner = errors.New("chain: unknown SignerID (not in RequireSigners set)")

// ErrTimestampInverted — receipt's Timestamp is earlier than the
// predecessor's.
var ErrTimestampInverted = errors.New("chain: receipt timestamp earlier than predecessor (chain is not temporally ordered)")

// ErrEmptySignature — receipt is missing its signature.
var ErrEmptySignature = errors.New("chain: receipt missing signature")

// ErrSignatureMismatch — receipt's signature did not verify under
// the supplied verifier.
var ErrSignatureMismatch = errors.New("chain: signature did not verify")
