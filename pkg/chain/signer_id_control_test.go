package chain

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// ===== signer_id control-character / canonical-bytes injection guard =====
//
// SignerID is an open free-form type and CanonicalBytes() serializes it
// with an in-band, UNESCAPED newline+colon delimiter:
//
//	fmt.Fprintf(&b, "signer_id: %s\n", string(r.SignerID))
//
// A signer_id containing a newline therefore injects extra signed lines
// (e.g. a forged `timestamp:` value) into the canonical bytes that get
// HMAC-signed and re-derived on verify, producing an ambiguous /
// duplicate-field signed form and breaking the cross-substrate byte-
// identity promise. These tests pin the additive control-char guard at
// the three trust boundaries (Verify, AppendSigned, ValidateReceiptShape)
// and are discrimination-proven: each fails if the guard is reverted.

// TestCanonicalBytes_InjectionPoC demonstrates (without the guard
// engaged on a non-Verify path) that a newline in SignerID injects a
// forged field into the signed canonical bytes. It is here as a living
// record of the underlying defect; the guard tests below assert it is
// now rejected at the trust boundaries.
func TestCanonicalBytes_InjectionPoC(t *testing.T) {
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("alice\ntimestamp: 2099-01-01T00:00:00Z"),
		Timestamp:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Signature:       "sig:x",
	}
	cb := r.CanonicalBytes()
	// The forged timestamp line (from the injected signer_id) AND the
	// real timestamp line both appear — an ambiguous duplicate-field
	// signed form. This is the defect the guard prevents from ever
	// being minted or accepted.
	if !bytes.Contains(cb, []byte("timestamp: 2099-01-01T00:00:00Z")) {
		t.Fatalf("PoC precondition: forged timestamp line not present in canonical bytes:\n%s", cb)
	}
	if !bytes.Contains(cb, []byte("timestamp: 2026-01-01T00:00:00Z")) {
		t.Fatalf("PoC precondition: real timestamp line not present in canonical bytes:\n%s", cb)
	}
	if strings.Count(string(cb), "timestamp: ") != 2 {
		t.Fatalf("PoC precondition: expected 2 timestamp lines (forged + real), got:\n%s", cb)
	}
}

// TestVerify_RejectsNewlineSignerID is the PRIMARY verifier-boundary
// guard: a maliciously-crafted (e.g. Imported) chain whose receipt
// signer_id contains a newline must fail Verify with
// ErrSignerIDControlChar BEFORE any prev-hash / signature work.
func TestVerify_RejectsNewlineSignerID(t *testing.T) {
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("alice\ntimestamp: 2099-01-01T00:00:00Z"),
		Timestamp:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Signature:       "sig:x",
	})
	// Structural verify (nil verifier) must already reject it.
	err := c.Verify(nil)
	if !errors.Is(err, ErrSignerIDControlChar) {
		t.Fatalf("Verify(nil): got %v, want ErrSignerIDControlChar", err)
	}
}

// TestVerify_RejectsCarriageReturnSignerID covers a second control char
// (CR) at the verifier boundary.
func TestVerify_RejectsCarriageReturnSignerID(t *testing.T) {
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("bob\rinjected"),
		Timestamp:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Signature:       "sig:x",
	})
	err := c.Verify(nil)
	if !errors.Is(err, ErrSignerIDControlChar) {
		t.Fatalf("Verify(nil): got %v, want ErrSignerIDControlChar", err)
	}
}

// TestAppendSigned_RejectsControlCharSigner is the construction-boundary
// guard: callers cannot MINT an injecting receipt.
func TestAppendSigned_RejectsControlCharSigner(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "n"}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := c.AppendSigned(signer, SignerID("alice\ntimestamp: 2099-01-01T00:00:00Z"), []byte("p"), t0)
	if !errors.Is(err, ErrSignerIDControlChar) {
		t.Fatalf("AppendSigned: got %v, want ErrSignerIDControlChar", err)
	}
	if c.Len() != 0 {
		t.Fatalf("AppendSigned appended an injecting receipt: chain len=%d, want 0", c.Len())
	}
}

// TestValidateReceiptShape_RejectsControlCharSigner is the defense-in-
// depth guard at the shape-validation boundary.
func TestValidateReceiptShape_RejectsControlCharSigner(t *testing.T) {
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("alice\nbob"),
		Timestamp:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Signature:       "sig:x",
	}
	err := ValidateReceiptShape(r)
	if !errors.Is(err, ErrSignerIDControlChar) {
		t.Fatalf("ValidateReceiptShape: got %v, want ErrSignerIDControlChar", err)
	}
}

// TestVerify_NormalSignerStillGreen is the regression guard: a normal
// signer_id like "delve" must still verify green (no false positives;
// byte-identity preserved for all legitimate signer_ids).
func TestVerify_NormalSignerStillGreen(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "ok"}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.AppendSigned(signer, SignerID("delve"), []byte("p"), t0); err != nil {
		t.Fatalf("AppendSigned(delve): %v", err)
	}
	if err := c.Verify(nil); err != nil {
		t.Fatalf("Verify(nil) on normal signer chain: %v", err)
	}
	// The five canonical pipeline signer names must also all be accepted
	// by the helper (no false positives on legitimate ids).
	for _, s := range []SignerID{"delve", "grounded", "recall", "echo", "parallax"} {
		if signerIDHasControlChars(s) {
			t.Fatalf("legitimate signer %q flagged as control-char", s)
		}
	}
}
