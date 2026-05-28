package chain

// cohort.go pins the R174 5-of-5 cohort surface for the limitless-
// audit-chain SDK. The cohort 5-pack is:
//
//	1. mirrormark — L43 Mirror-Mark v1 substrate (verify.go's
//	   MirrorMarkSigner / MirrorMarkVerifier + the four MirrorMark*
//	   constants are the wire-format pin)
//	2. kat        — R151 KAT-1 cross-substrate invariant anchor
//	   (KAT1_HMAC_SHA256_HEX + canonical inputs)
//	3. honest     — R143 LOUD-ONCE-WARNING-FLAG (the SDK exposes
//	   LoudOnce so callers can instrument boundary-saturation
//	   advisories the cohort way)
//	4. legal      — R166 LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL
//	   sentinel (typed const + honest-default bool)
//	5. manifest   — R-AI-CAPABILITY-MANIFEST (the SDK's self-
//	   description: name + version + KAT-1 commitment so a regulator
//	   reading the binary can re-derive the cohort fingerprint)
//
// The five pillars live in this single Go file (rather than five
// sub-packages) per the cohort discipline that "5-of-5 means five
// concerns ARE PRESENT, not five directories required" — a
// substrate-native idiom (R157). The Rust port uses module-per-file
// because Rust idiom is module-per-file; the Go port uses one-file-
// many-types because that is the Go idiom.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
)

// ===== Pillar 2: kat (R151 KAT-1 cohort invariant anchor) =====

// KAT1HMACSHA256Hex is the cohort-canonical KAT-1 HMAC-SHA256 digest,
// hex-encoded. Pinned byte-identical to foundation/pkg/mirrormark and
// to every cohort substrate port.
//
// Reproduce via OpenSSL (no Go toolchain required):
//
//	printf '\x01' > /tmp/kat1.bin
//	printf '\x00%.0s' $(seq 1 32) >> /tmp/kat1.bin
//	openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
//	# -> 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
const KAT1HMACSHA256Hex = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

// KAT1PublishedMark is the cohort-canonical KAT-1 Mirror-Mark string.
// 62 characters: "lore@v1:" + 54-char base64url body. Byte-identical
// across every R151 substrate port.
const KAT1PublishedMark = "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg"

// KAT1InputLen is the canonical KAT-1 input length (1-byte version tag
// + 32-byte zero corpus = 33 bytes).
const KAT1InputLen = 33

// KAT1CanonicalInput returns the cohort-canonical 33-byte KAT-1 HMAC
// input: 0x01 || 32×0x00. A fresh copy each call.
func KAT1CanonicalInput() []byte {
	out := make([]byte, KAT1InputLen)
	out[0] = MirrorMarkVersion
	return out
}

// KAT1CanonicalKey returns the cohort-canonical KAT-1 HMAC key (empty).
func KAT1CanonicalKey() []byte { return []byte{} }

// KAT1CorpusSHA returns the cohort-canonical KAT-1 corpus SHA (32 zero
// bytes). Returns a fresh copy each call.
func KAT1CorpusSHA() [sha256.Size]byte {
	return [sha256.Size]byte{}
}

// AssertKAT1Parity computes the KAT-1 HMAC-SHA256 hex from the SDK's
// own canonical-input / canonical-key helpers and compares to
// KAT1HMACSHA256Hex. Returns nil if equal; ErrKAT1Drift otherwise.
//
// Wired into TestAssertKAT1Parity (chain_test.go) per the R145.C
// FIREWALL-TEST-DISCIPLINE — any code-path that changes the KAT-1
// substrate fails this test before reaching CI.
//
// Also exposed publicly so consumers can call it from their own
// boot-time self-check (e.g. a flagship's init() can refuse to start
// if the SDK fails KAT-1 parity, surfacing supply-chain tampering).
func AssertKAT1Parity() error {
	// For KAT-1 specifically, the canonical input ALREADY includes
	// the version-tag-prefix-and-corpus (the input is 0x01 || 32×0x00,
	// i.e. version-tag + zero-corpus inline), so we compute the HMAC
	// directly over the 33-byte canonical input rather than going
	// through MirrorMarkSigner.Sign (which prepends version+corpus).
	//
	// This matches the cohort KAT-1 recipe:
	//   HMAC-SHA256(key="", input = 0x01 || 32×0x00)
	got := computeKAT1Hex(KAT1CanonicalInput(), KAT1CanonicalKey())
	if got != KAT1HMACSHA256Hex {
		return fmt.Errorf("%w: computed=%s, expected=%s",
			ErrKAT1Drift, got, KAT1HMACSHA256Hex)
	}
	return nil
}

// computeKAT1Hex is the canonical KAT-1 HMAC-SHA256 hex computation.
// Direct HMAC over the 33-byte canonical input with the canonical key.
// Separated from MirrorMarkSigner.Sign because KAT-1's canonical input
// is the FULL 33-byte HMAC input (version-tag included), not a payload
// to be wrapped — MirrorMarkSigner is for signing arbitrary payloads.
func computeKAT1Hex(input []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	digest := mac.Sum(nil)
	return hex.EncodeToString(digest)
}

// ErrKAT1Drift — AssertKAT1Parity computed a digest that does not
// match KAT1HMACSHA256Hex. Indicates the SDK's substrate has drifted
// from the cohort canonical wire format — a R145.C firewall fail.
var ErrKAT1Drift = errors.New("cohort: KAT-1 HMAC-SHA256 drift (substrate divergence)")

// ===== Pillar 3: honest (R143 LOUD-ONCE-WARNING-FLAG) =====

// LoudOnce is the cohort R143 LOUD-ONCE-WARNING-FLAG primitive.
//
// A LoudOnce fires once. Subsequent TryFire calls return false. The
// gate is atomic and goroutine-safe. Per R143 the warning is loud-
// once (not loud-forever) so the cohort's hot-path advisories do not
// flood logs.
//
// Usage:
//
//	var GATE = chain.NewLoudOnce()
//
//	if GATE.TryFire() {
//	    log.Printf("[LOUD-ONCE-WARNING][warning][MYAPP_CLAMP] " +
//	        "boundary saturated; audit_rule=R143_LOUD_ONCE_WARNING_FLAG")
//	}
//
// The zero-value LoudOnce is NOT a valid LoudOnce — callers MUST
// construct via NewLoudOnce. (A zero-value would conflict with the
// CAS semantics if we used 0 == "fired" without a sentinel.)
type LoudOnce struct {
	fired atomic.Bool
}

// NewLoudOnce returns a fresh un-fired LoudOnce.
func NewLoudOnce() *LoudOnce { return &LoudOnce{} }

// TryFire returns true exactly once for the LoudOnce's lifetime —
// the first call that wins the CAS. Subsequent calls return false.
// Goroutine-safe.
func (o *LoudOnce) TryFire() bool {
	return o.fired.CompareAndSwap(false, true)
}

// HasFired reports whether the LoudOnce has fired. Does NOT consume
// the gate. Useful for tests + readiness probes.
func (o *LoudOnce) HasFired() bool { return o.fired.Load() }

// reset is a test-only helper used by chain_test.go to re-arm a
// LoudOnce between assertions. Not part of the public API — the
// production discipline is "loud-once means loud-once, period".
//
//nolint:unused // used by chain_test.go via package-internal access
func (o *LoudOnce) reset() { o.fired.Store(false) }

// ===== Pillar 4: legal (R166 LIABILITY-FOOTER-CONST) =====

// LiabilityFooter is the cohort-canonical liability disclosure footer.
// Grep-discoverable string consumers SHOULD embed (or override) on any
// audit-chain surface that crosses a trust boundary.
//
// The text is intentionally short + machine-grep-friendly: "NOT YET"
// is the canonical regulator-readable signal that the SDK has not
// been counsel-reviewed for production use.
const LiabilityFooter = "Limitless audit-chain SDK — NOT YET reviewed by counsel for regulator submission. Cohort canonical substrate; consumer flagships override on their own R145.B branch."

// ReviewedByCounsel is the cohort-canonical "has counsel signed off?"
// boolean. HONEST-DEFAULT: false. Flipping to true is an R145.B
// behaviour-changing event requiring its own branch + a counsel-
// signoff commit.
//
// Consumers MAY override (per consumer flagship) — the SDK itself
// stays at false because the SDK is substrate, not a counsel-reviewed
// production surface.
const ReviewedByCounsel = false

// LibraryRecommendsHostActs is the cohort-canonical phrase used by
// liability-footer copy to clarify that the library RECOMMENDS, while
// the HOST acts. The two-noun split matters: the library is advisory;
// the host (the deploying flagship) is the actor accountable for
// regulator submissions.
const LibraryRecommendsHostActs = "library recommends; host acts"

// ===== Pillar 5: manifest (R-AI-CAPABILITY-MANIFEST) =====

// ManifestRecord is the cohort self-description for the audit-chain
// SDK. A regulator reading the binary can recompute the KAT-1
// commitment + compare the manifest name/version to the published
// fingerprint, confirming supply-chain integrity at line 0.
type ManifestRecord struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	KAT1Digest  string `json:"kat1_digest"`
	WireFormat  string `json:"wire_format"`
	Description string `json:"description"`
}

// SDKVersion is the cohort-canonical version string of this SDK.
// Bumped on R145.B SIBLING-NOT-STACKED branches when the wire format
// changes (which requires a MirrorMarkVersion bump per R151).
const SDKVersion = "0.1.0"

// Manifest returns the audit-chain SDK's self-description. Returned
// fresh each call (no shared state).
func Manifest() ManifestRecord {
	return ManifestRecord{
		Name:        "limitless-audit-chain",
		Version:     SDKVersion,
		KAT1Digest:  KAT1HMACSHA256Hex,
		WireFormat:  "v1 Mirror-Mark over canonical (prev_receipt_hash || payload_hash || signer_id || timestamp)",
		Description: "Cohort-canonical audit-chain primitive. Generalises beyond delve→grounded→recall→echo→parallax — any cross-infra or cross-flagship handoff can sign + verify here.",
	}
}
