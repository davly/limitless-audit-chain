package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// ===== Canonical bytes + hash determinism =====

func mkPayloadHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestCanonicalBytes_StableOrdering(t *testing.T) {
	ts := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("hello"),
		SignerID:        SignerID("delve"),
		Timestamp:       ts,
		Signature:       "irrelevant-for-canonical-bytes",
	}
	got := string(r.CanonicalBytes())
	want := "payload_hash: " + mkPayloadHash("hello") + "\n" +
		"prev_receipt_hash: " + GenesisPrevHash + "\n" +
		"signer_id: delve\n" +
		"timestamp: 2026-05-28T12:00:00Z\n"
	if got != want {
		t.Fatalf("CanonicalBytes drift:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestCanonicalBytes_ByteIdenticalToI20Demo(t *testing.T) {
	// Byte-identical pin to flagships/limitless-audit-chain-demo/
	// internal/chain.Receipt.CanonicalBytes — the SDK MUST stay
	// wire-compatible with the I20 first-saturator.
	ts := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("delve-payload"),
		SignerID:        SignerID("delve"),
		Timestamp:       ts,
		Signature:       "sig-not-in-canonical",
	}
	got := string(r.CanonicalBytes())
	if !strings.HasPrefix(got, "payload_hash: ") {
		t.Fatalf("expected 'payload_hash: ' first line, got %q", got)
	}
	if !strings.Contains(got, "\nsigner_id: delve\n") {
		t.Fatalf("missing signer_id line in %q", got)
	}
}

func TestCanonicalBytes_TimestampIsUTC(t *testing.T) {
	// Even if caller passes non-UTC, canonical bytes emit UTC.
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skipf("LA tz unavailable: %v", err)
	}
	ts := time.Date(2026, 5, 28, 5, 0, 0, 0, loc)
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       ts,
	}
	got := string(r.CanonicalBytes())
	if !strings.Contains(got, "timestamp: 2026-05-28T12:00:00Z\n") {
		t.Fatalf("expected UTC-normalised timestamp in %q", got)
	}
}

func TestHash_Deterministic(t *testing.T) {
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	}
	first := r.Hash()
	for i := 0; i < 50; i++ {
		if got := r.Hash(); got != first {
			t.Fatalf("iter %d: non-deterministic Hash:\n  iter 0: %s\n  iter %d: %s", i, first, i, got)
		}
	}
}

func TestHash_HexLowercase64Chars(t *testing.T) {
	r := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	}
	got := r.Hash()
	if len(got) != PrevHashLen {
		t.Fatalf("Hash length: got %d, want %d", len(got), PrevHashLen)
	}
	for i, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("Hash[%d]=%q: expected lowercase hex", i, c)
		}
	}
}

func TestHashPayload_KnownVector(t *testing.T) {
	// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	got := HashPayload(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("HashPayload empty: got %s, want %s", got, want)
	}
}

func TestIsGenesis(t *testing.T) {
	r := Receipt{PrevReceiptHash: GenesisPrevHash}
	if !r.IsGenesis() {
		t.Fatalf("IsGenesis false on genesis sentinel")
	}
	r2 := Receipt{PrevReceiptHash: "anything-else"}
	if r2.IsGenesis() {
		t.Fatalf("IsGenesis true on non-sentinel")
	}
}

func TestSignerID_String(t *testing.T) {
	s := SignerID("delve")
	if s.String() != "delve" {
		t.Fatalf("SignerID.String drift: got %q", s.String())
	}
}

// ===== ValidateReceiptShape =====

func okReceipt() Receipt {
	return Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "sig",
	}
}

func TestValidateReceiptShape_Ok(t *testing.T) {
	if err := ValidateReceiptShape(okReceipt()); err != nil {
		t.Fatalf("unexpected error on ok receipt: %v", err)
	}
}

func TestValidateReceiptShape_PrevHashWrongLength(t *testing.T) {
	r := okReceipt()
	r.PrevReceiptHash = "tooshort"
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapePrevHashLen) {
		t.Fatalf("got %v, want ErrShapePrevHashLen", err)
	}
}

func TestValidateReceiptShape_PrevHashNotHex(t *testing.T) {
	r := okReceipt()
	r.PrevReceiptHash = strings.Repeat("Z", PrevHashLen)
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapePrevHashNotHex) {
		t.Fatalf("got %v, want ErrShapePrevHashNotHex", err)
	}
}

func TestValidateReceiptShape_PayloadHashWrongLength(t *testing.T) {
	r := okReceipt()
	r.PayloadHash = "too-short"
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapePayloadHashLen) {
		t.Fatalf("got %v, want ErrShapePayloadHashLen", err)
	}
}

func TestValidateReceiptShape_PayloadHashNotHex(t *testing.T) {
	r := okReceipt()
	r.PayloadHash = strings.Repeat("g", PayloadHashLen)
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapePayloadHashNotHex) {
		t.Fatalf("got %v, want ErrShapePayloadHashNotHex", err)
	}
}

func TestValidateReceiptShape_EmptySigner(t *testing.T) {
	r := okReceipt()
	r.SignerID = ""
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapeEmptySigner) {
		t.Fatalf("got %v, want ErrShapeEmptySigner", err)
	}
}

func TestValidateReceiptShape_ZeroTimestamp(t *testing.T) {
	r := okReceipt()
	r.Timestamp = time.Time{}
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapeZeroTimestamp) {
		t.Fatalf("got %v, want ErrShapeZeroTimestamp", err)
	}
}

func TestValidateReceiptShape_EmptySignature(t *testing.T) {
	r := okReceipt()
	r.Signature = ""
	if err := ValidateReceiptShape(r); !errors.Is(err, ErrShapeEmptySignature) {
		t.Fatalf("got %v, want ErrShapeEmptySignature", err)
	}
}

func TestGenesisPrevHash_AllZeroHex(t *testing.T) {
	if len(GenesisPrevHash) != 64 {
		t.Fatalf("GenesisPrevHash length: got %d, want 64", len(GenesisPrevHash))
	}
	for i, c := range GenesisPrevHash {
		if c != '0' {
			t.Fatalf("GenesisPrevHash[%d]=%q, want '0'", i, c)
		}
	}
}
