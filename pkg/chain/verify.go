package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// VerifierFunc verifies the signature of a single receipt. The chain
// library calls this once per receipt, in append order, during Verify.
//
// The function receives the WHOLE receipt (canonical bytes can be
// re-derived via r.CanonicalBytes()) so that signature schemes which
// need to inspect SignerID for key-dispatch can do so. Return nil on
// success; any non-nil error short-circuits chain.Verify.
type VerifierFunc func(r Receipt) error

// Signer signs the canonical bytes of a receipt. Plugged into
// Chain.AppendSigned so callers don't need to construct receipts +
// signatures manually.
//
// Substrate-agnostic: any deterministic signature scheme works (HMAC,
// ed25519, RSA, ECDSA, secp256k1, ...). The chain layer treats the
// returned signature as opaque.
type Signer interface {
	// Sign returns the signature over canonical, as a printable
	// string (base64url for HMAC, hex for ed25519, etc.). Error
	// causes Chain.AppendSigned to return without appending.
	Sign(canonical []byte) (string, error)
}

// Verify walks the chain bottom-up (genesis → tip) and rejects on the
// first failure. Returns nil iff:
//
//   - The chain is non-empty AND
//   - Receipt[0].PrevReceiptHash == GenesisPrevHash AND
//   - Every receipt's SignerID is allowed under RequireSigners AND
//   - Every receipt's Signature is non-empty AND
//   - For each i > 0:
//     Receipts[i].PrevReceiptHash == Receipts[i-1].Hash() AND
//     Receipts[i].Timestamp >= Receipts[i-1].Timestamp AND
//   - Every receipt's signature verifies under verifier.
//
// Bottom-up means chronological (genesis → tip). The cohort discipline
// names this "bottom-up" because the chain is a tree whose leaves are
// the emitter outputs and whose root is the genesis. We walk from root
// → leaves, which is bottom-to-top of the trust hierarchy (the genesis
// is the trust anchor).
//
// Verifier is allowed to be nil — if so, signature verification is
// SKIPPED (structural verification only). This is useful for callers
// that want to inspect chain structure before paying for cryptographic
// verification (e.g. a CLI's "inspect" mode). PRODUCTION code paths
// MUST pass a real verifier.
func (c *Chain) Verify(verifier VerifierFunc) error {
	if len(c.Receipts) == 0 {
		return ErrEmptyChain
	}
	if c.Receipts[0].PrevReceiptHash != GenesisPrevHash {
		return ErrGenesisPrevHash
	}
	for i, r := range c.Receipts {
		if !c.IsAllowedSigner(r.SignerID) {
			return fmt.Errorf("%w: receipt[%d].SignerID=%q", ErrUnknownSigner, i, r.SignerID)
		}
		if r.Signature == "" {
			return fmt.Errorf("%w: receipt[%d]", ErrEmptySignature, i)
		}
		if i > 0 {
			parent := c.Receipts[i-1]
			expected := parent.Hash()
			if r.PrevReceiptHash != expected {
				return fmt.Errorf("%w: receipt[%d].PrevReceiptHash=%s, expected=%s",
					ErrPrevHashMismatch, i, r.PrevReceiptHash, expected)
			}
			if r.Timestamp.Before(parent.Timestamp) {
				return fmt.Errorf("%w: receipt[%d].Timestamp=%s, parent=%s",
					ErrTimestampInverted, i,
					r.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
					parent.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"))
			}
		}
		if verifier != nil {
			if err := verifier(r); err != nil {
				// Wrap both ErrSignatureMismatch (so callers can
				// match on the chain-layer sentinel) and the
				// underlying verifier error (so callers can match
				// on substrate-level sentinels via errors.Is). Use
				// fmt.Errorf's %w in TWO positions — Go 1.20+
				// supports a single error wrapping multiple errors
				// via errors.Join.
				return errors.Join(
					ErrSignatureMismatch,
					fmt.Errorf("receipt[%d] signer=%s: %w", i, r.SignerID, err),
				)
			}
		}
	}
	return nil
}

// VerifyStructural is Verify with a nil verifier — structural-only
// (prev-hash chain + ordering + shape) without cryptographic
// verification. Convenience method for the CLI's `inspect` subcommand.
func (c *Chain) VerifyStructural() error {
	return c.Verify(nil)
}

// ----- Mirror-Mark HMAC signer / verifier (cohort canonical) -----
//
// The cohort-canonical KAT-1 substrate is HMAC-SHA256 over the Mirror-
// Mark v1 wire format. The audit-chain SDK ships a built-in Mirror-
// Mark signer + verifier so callers using the canonical substrate
// don't need to wire one up themselves; non-Mirror-Mark callers (e.g.
// ed25519, secp256k1) implement their own Signer / VerifierFunc.

// MirrorMarkPrefix is the documented header-value prefix for v1
// Mirror-Marks. Byte-identical to foundation/pkg/mirrormark.MarkPrefix
// and to every cohort port.
const MirrorMarkPrefix = "lore@v1:"

// MirrorMarkVersion is the 1-byte tag prefixing the HMAC input.
const MirrorMarkVersion byte = 0x01

// MirrorMarkCorpusPrefixLen is the corpus-SHA prefix length embedded
// in the mark body (8 bytes).
const MirrorMarkCorpusPrefixLen = 8

// MirrorMarkBodyLen is the unencoded length of the mark body (40 bytes).
const MirrorMarkBodyLen = MirrorMarkCorpusPrefixLen + sha256.Size

// MirrorMarkSigner wraps (corpusSHA, key) as a Signer that emits
// cohort-canonical v1 Mirror-Marks. Byte-identical output to
// foundation/pkg/mirrormark and to every cohort substrate port.
type MirrorMarkSigner struct {
	CorpusSHA [sha256.Size]byte
	Key       []byte
}

// Sign returns the canonical Mirror-Mark for the canonical bytes.
//
// Wire format:
//
//	"lore@v1:" + base64url( corpusSHA[:8] || hmacSHA256(0x01 || corpusSHA || canonical, key) )
func (s *MirrorMarkSigner) Sign(canonical []byte) (string, error) {
	if s == nil {
		return "", ErrMirrorMarkNilSigner
	}
	mac := hmac.New(sha256.New, s.Key)
	_, _ = mac.Write([]byte{MirrorMarkVersion})
	_, _ = mac.Write(s.CorpusSHA[:])
	_, _ = mac.Write(canonical)
	digest := mac.Sum(nil)

	body := make([]byte, 0, MirrorMarkBodyLen)
	body = append(body, s.CorpusSHA[:MirrorMarkCorpusPrefixLen]...)
	body = append(body, digest...)
	return MirrorMarkPrefix + base64.RawURLEncoding.EncodeToString(body), nil
}

// ErrMirrorMarkNilSigner — Sign called on nil MirrorMarkSigner.
var ErrMirrorMarkNilSigner = errors.New("chain: nil MirrorMarkSigner")

// MirrorMarkVerifier returns a VerifierFunc that checks each receipt's
// signature as a v1 Mirror-Mark against (corpusSHA, key).
//
// The verifier re-derives canonical bytes from the Receipt fields,
// recomputes the HMAC, and constant-time-compares the digest. Returns
// a typed sentinel on any failure.
func MirrorMarkVerifier(corpusSHA [sha256.Size]byte, key []byte) VerifierFunc {
	keyCopy := append([]byte(nil), key...)
	return func(r Receipt) error {
		mark := r.Signature
		if len(mark) < len(MirrorMarkPrefix) || mark[:len(MirrorMarkPrefix)] != MirrorMarkPrefix {
			return ErrMirrorMarkUnknownVersion
		}
		body, err := base64.RawURLEncoding.DecodeString(mark[len(MirrorMarkPrefix):])
		if err != nil {
			return ErrMirrorMarkMalformed
		}
		if len(body) != MirrorMarkBodyLen {
			return ErrMirrorMarkMalformed
		}
		corpusPrefix := body[:MirrorMarkCorpusPrefixLen]
		digest := body[MirrorMarkCorpusPrefixLen:]
		if !hmac.Equal(corpusPrefix, corpusSHA[:MirrorMarkCorpusPrefixLen]) {
			return ErrMirrorMarkCorpusMismatch
		}
		mac := hmac.New(sha256.New, keyCopy)
		_, _ = mac.Write([]byte{MirrorMarkVersion})
		_, _ = mac.Write(corpusSHA[:])
		_, _ = mac.Write(r.CanonicalBytes())
		want := mac.Sum(nil)
		if !hmac.Equal(digest, want) {
			return ErrMirrorMarkSignatureMismatch
		}
		return nil
	}
}

// ----- Mirror-Mark error sentinels -----

// ErrMirrorMarkUnknownVersion — mark missing canonical prefix.
var ErrMirrorMarkUnknownVersion = errors.New("mirrormark: unknown version (missing 'lore@v1:' prefix)")

// ErrMirrorMarkMalformed — base64url decode failed or wrong body length.
var ErrMirrorMarkMalformed = errors.New("mirrormark: malformed mark")

// ErrMirrorMarkCorpusMismatch — corpus prefix in mark != supplied corpus SHA.
var ErrMirrorMarkCorpusMismatch = errors.New("mirrormark: corpus prefix mismatch")

// ErrMirrorMarkSignatureMismatch — HMAC digest mismatch.
var ErrMirrorMarkSignatureMismatch = errors.New("mirrormark: HMAC signature mismatch")
