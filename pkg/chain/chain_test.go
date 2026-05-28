package chain

import (
	"errors"
	"testing"
	"time"
)

// alwaysValidVerifier — accepts every signature. Used by tests focused
// on the chain composition layer.
func alwaysValidVerifier(_ Receipt) error { return nil }

// fixedHMACSigner is a test-only Signer that emits a deterministic
// "sig:" + last 4 bytes of canonical-bytes-XORed-into-zero — enough to
// be a non-empty string but useless cryptographically. Tests use it to
// hit Chain.AppendSigned without pulling crypto/hmac dependencies into
// the test file.
type fixedHMACSigner struct{ tag string }

func (f *fixedHMACSigner) Sign(canonical []byte) (string, error) {
	if len(canonical) == 0 {
		return "", errors.New("empty canonical")
	}
	return "sig:" + f.tag, nil
}

// ===== Empty / Genesis / structural =====

func TestNewChain_EmptyIsZero(t *testing.T) {
	c := NewChain()
	if c.Len() != 0 {
		t.Fatalf("NewChain Len: got %d, want 0", c.Len())
	}
	if _, ok := c.Tip(); ok {
		t.Fatalf("Tip ok=true on empty chain")
	}
	if _, ok := c.Genesis(); ok {
		t.Fatalf("Genesis ok=true on empty chain")
	}
}

func TestVerify_EmptyChainRejected(t *testing.T) {
	c := NewChain()
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrEmptyChain) {
		t.Fatalf("empty chain: got %v, want ErrEmptyChain", err)
	}
}

func TestVerify_GenesisMustHaveSentinelPrevHash(t *testing.T) {
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: "not-the-sentinel",
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "sig",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrGenesisPrevHash) {
		t.Fatalf("bad genesis: got %v, want ErrGenesisPrevHash", err)
	}
}

func TestVerify_EmptySignatureRejected(t *testing.T) {
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrEmptySignature) {
		t.Fatalf("empty sig: got %v, want ErrEmptySignature", err)
	}
}

func TestVerify_PrevHashMismatchRejected(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("a"),
		SignerID:        SignerID("delve"),
		Timestamp:       t0,
		Signature:       "sig0",
	})
	c.Append(Receipt{
		PrevReceiptHash: "wrong-hash",
		PayloadHash:     mkPayloadHash("b"),
		SignerID:        SignerID("grounded"),
		Timestamp:       t0.Add(time.Second),
		Signature:       "sig1",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrPrevHashMismatch) {
		t.Fatalf("prev-hash mismatch: got %v, want ErrPrevHashMismatch", err)
	}
}

func TestVerify_TimestampInversionRejected(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r0 := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("a"),
		SignerID:        SignerID("delve"),
		Timestamp:       t0,
		Signature:       "sig0",
	}
	c := NewChain()
	c.Append(r0)
	c.Append(Receipt{
		PrevReceiptHash: r0.Hash(),
		PayloadHash:     mkPayloadHash("b"),
		SignerID:        SignerID("grounded"),
		Timestamp:       t0.Add(-time.Hour), // earlier than parent
		Signature:       "sig1",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrTimestampInverted) {
		t.Fatalf("timestamp inversion: got %v, want ErrTimestampInverted", err)
	}
}

func TestVerify_SignatureMismatchPropagatesVerifierError(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	rejectingVerifier := func(_ Receipt) error { return errors.New("rejected by test verifier") }
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       t0,
		Signature:       "tampered",
	})
	if err := c.Verify(rejectingVerifier); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("signature mismatch: got %v, want ErrSignatureMismatch", err)
	}
}

func TestVerify_FiveStepChainSucceeds(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	c := NewChain()
	r0 := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("delve-payload"),
		SignerID:        SignerID("delve"),
		Timestamp:       t0,
		Signature:       "sig0",
	}
	c.Append(r0)
	r1 := Receipt{
		PrevReceiptHash: r0.Hash(),
		PayloadHash:     mkPayloadHash("grounded-payload"),
		SignerID:        SignerID("grounded"),
		Timestamp:       t0.Add(time.Second),
		Signature:       "sig1",
	}
	c.Append(r1)
	r2 := Receipt{
		PrevReceiptHash: r1.Hash(),
		PayloadHash:     mkPayloadHash("recall-payload"),
		SignerID:        SignerID("recall"),
		Timestamp:       t0.Add(2 * time.Second),
		Signature:       "sig2",
	}
	c.Append(r2)
	r3 := Receipt{
		PrevReceiptHash: r2.Hash(),
		PayloadHash:     mkPayloadHash("echo-payload"),
		SignerID:        SignerID("echo"),
		Timestamp:       t0.Add(3 * time.Second),
		Signature:       "sig3",
	}
	c.Append(r3)
	r4 := Receipt{
		PrevReceiptHash: r3.Hash(),
		PayloadHash:     mkPayloadHash("parallax-payload"),
		SignerID:        SignerID("parallax"),
		Timestamp:       t0.Add(4 * time.Second),
		Signature:       "sig4",
	}
	c.Append(r4)

	if err := c.Verify(alwaysValidVerifier); err != nil {
		t.Fatalf("five-step chain Verify: %v", err)
	}
	if c.Len() != 5 {
		t.Fatalf("Len: got %d, want 5", c.Len())
	}
	wantOrder := []SignerID{"delve", "grounded", "recall", "echo", "parallax"}
	got := c.SignerSequence()
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Fatalf("SignerSequence[%d]: got %s, want %s", i, got[i], wantOrder[i])
		}
	}
}

func TestVerify_TamperingMiddleReceiptBreaksChain(t *testing.T) {
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r0 := Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("a"),
		SignerID:        SignerID("delve"),
		Timestamp:       t0,
		Signature:       "sig0",
	}
	r1 := Receipt{
		PrevReceiptHash: r0.Hash(),
		PayloadHash:     mkPayloadHash("b"),
		SignerID:        SignerID("grounded"),
		Timestamp:       t0.Add(time.Second),
		Signature:       "sig1",
	}
	r2 := Receipt{
		PrevReceiptHash: r1.Hash(),
		PayloadHash:     mkPayloadHash("c"),
		SignerID:        SignerID("recall"),
		Timestamp:       t0.Add(2 * time.Second),
		Signature:       "sig2",
	}
	// Tamper with r1's PayloadHash AFTER r2 captured its hash.
	r1.PayloadHash = mkPayloadHash("b-evil")
	c := NewChain()
	c.Append(r0)
	c.Append(r1)
	c.Append(r2)
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrPrevHashMismatch) {
		t.Fatalf("tampering middle receipt: got %v, want ErrPrevHashMismatch", err)
	}
}

// ===== RequireSigners closed-set enforcement =====

func TestIsAllowedSigner_DefaultAcceptsAny(t *testing.T) {
	c := NewChain()
	if !c.IsAllowedSigner(SignerID("anything")) {
		t.Fatalf("default policy rejected non-empty SignerID")
	}
	if c.IsAllowedSigner("") {
		t.Fatalf("default policy accepted empty SignerID")
	}
}

func TestIsAllowedSigner_RequireSignersEnforces(t *testing.T) {
	c := NewChain()
	c.RequireSigners = []SignerID{"delve", "grounded"}
	if !c.IsAllowedSigner("delve") {
		t.Fatalf("delve rejected under RequireSigners=[delve, grounded]")
	}
	if c.IsAllowedSigner("rogue") {
		t.Fatalf("rogue accepted under RequireSigners=[delve, grounded]")
	}
}

func TestVerify_UnknownSignerRejectedUnderRequireSigners(t *testing.T) {
	c := NewChain()
	c.RequireSigners = []SignerID{"delve", "grounded"}
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("rogue"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "sig",
	})
	if err := c.Verify(alwaysValidVerifier); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer: got %v, want ErrUnknownSigner", err)
	}
}

// ===== AppendSigned =====

func TestAppendSigned_GenesisLink(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "g"}
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r, err := c.AppendSigned(signer, SignerID("delve"), []byte("payload-1"), now)
	if err != nil {
		t.Fatalf("AppendSigned: %v", err)
	}
	if r.PrevReceiptHash != GenesisPrevHash {
		t.Fatalf("genesis prev: got %s, want sentinel", r.PrevReceiptHash)
	}
	if r.PayloadHash != HashPayload([]byte("payload-1")) {
		t.Fatalf("payload hash drift")
	}
	if r.Signature != "sig:g" {
		t.Fatalf("signature drift: %s", r.Signature)
	}
	if c.Len() != 1 {
		t.Fatalf("Len after one append: %d", c.Len())
	}
}

func TestAppendSigned_LinkedTipChain(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "x"}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r0, err := c.AppendSigned(signer, SignerID("delve"), []byte("p0"), t0)
	if err != nil {
		t.Fatalf("AppendSigned#0: %v", err)
	}
	r1, err := c.AppendSigned(signer, SignerID("grounded"), []byte("p1"), t0.Add(time.Second))
	if err != nil {
		t.Fatalf("AppendSigned#1: %v", err)
	}
	if r1.PrevReceiptHash != r0.Hash() {
		t.Fatalf("r1 prev: got %s, want %s", r1.PrevReceiptHash, r0.Hash())
	}
}

func TestAppendSigned_RejectsNilSigner(t *testing.T) {
	c := NewChain()
	_, err := c.AppendSigned(nil, SignerID("delve"), []byte("x"), time.Now())
	if !errors.Is(err, ErrAppendNilSigner) {
		t.Fatalf("got %v, want ErrAppendNilSigner", err)
	}
}

func TestAppendSigned_RejectsEmptySigner(t *testing.T) {
	c := NewChain()
	_, err := c.AppendSigned(&fixedHMACSigner{tag: "x"}, SignerID(""), []byte("x"), time.Now())
	if !errors.Is(err, ErrShapeEmptySigner) {
		t.Fatalf("got %v, want ErrShapeEmptySigner", err)
	}
}

func TestAppendSigned_RejectsSignerNotInRequireSigners(t *testing.T) {
	c := NewChain()
	c.RequireSigners = []SignerID{"delve"}
	_, err := c.AppendSigned(&fixedHMACSigner{tag: "x"}, SignerID("rogue"), []byte("x"), time.Now())
	if !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("got %v, want ErrUnknownSigner", err)
	}
}

// ===== Tip / Genesis / Sequence =====

func TestTipAndGenesis(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "y"}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	r0, _ := c.AppendSigned(signer, SignerID("delve"), []byte("p0"), t0)
	r1, _ := c.AppendSigned(signer, SignerID("grounded"), []byte("p1"), t0.Add(time.Second))

	g, ok := c.Genesis()
	if !ok || g.SignerID != r0.SignerID {
		t.Fatalf("Genesis: got %+v ok=%v, want r0 ok=true", g, ok)
	}
	tip, ok := c.Tip()
	if !ok || tip.SignerID != r1.SignerID {
		t.Fatalf("Tip: got %+v ok=%v, want r1 ok=true", tip, ok)
	}
}

func TestSortedReceiptsCopy_DefensiveCopy(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "z"}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("p0"), t0)
	_, _ = c.AppendSigned(signer, SignerID("grounded"), []byte("p1"), t0.Add(time.Second))

	sorted := c.SortedReceiptsCopy()
	if len(sorted) != 2 {
		t.Fatalf("SortedReceiptsCopy len: got %d, want 2", len(sorted))
	}
	// Mutate the copy; original must be unaffected.
	sorted[0].PayloadHash = "MUTATED"
	orig, _ := c.Genesis()
	if orig.PayloadHash == "MUTATED" {
		t.Fatalf("SortedReceiptsCopy did not return a defensive copy")
	}
}

// ===== Export / Import roundtrip =====

func TestExportImport_RoundTripPreservesChain(t *testing.T) {
	c := NewChain()
	c.RequireSigners = []SignerID{"delve", "grounded"}
	c.Metadata = map[string]string{"cohort": "test", "purpose": "unit-test"}
	signer := &fixedHMACSigner{tag: "rt"}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("p0"), t0)
	_, _ = c.AppendSigned(signer, SignerID("grounded"), []byte("p1"), t0.Add(time.Second))

	wire, err := c.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	c2, err := Import(wire)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if c2.Len() != c.Len() {
		t.Fatalf("Len after roundtrip: got %d, want %d", c2.Len(), c.Len())
	}
	if c2.Metadata["cohort"] != "test" {
		t.Fatalf("metadata drift: %v", c2.Metadata)
	}
	if err := c2.Verify(alwaysValidVerifier); err != nil {
		t.Fatalf("Verify after roundtrip: %v", err)
	}
}

func TestExportCompact_Smaller(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "c"}
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("p"), time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))
	pretty, err := c.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	compact, err := c.ExportCompact()
	if err != nil {
		t.Fatalf("ExportCompact: %v", err)
	}
	if len(compact) >= len(pretty) {
		t.Fatalf("ExportCompact not smaller: compact=%d pretty=%d", len(compact), len(pretty))
	}
}

func TestImport_EmptyRejected(t *testing.T) {
	if _, err := Import(nil); !errors.Is(err, ErrImportEmpty) {
		t.Fatalf("Import nil: got %v, want ErrImportEmpty", err)
	}
}

func TestImport_MalformedRejected(t *testing.T) {
	if _, err := Import([]byte("{not-json")); !errors.Is(err, ErrImportMalformed) {
		t.Fatalf("Import malformed: got %v, want ErrImportMalformed", err)
	}
}

// ===== Structural-only verify =====

func TestVerifyStructural_AcceptsAnySignature(t *testing.T) {
	c := NewChain()
	signer := &fixedHMACSigner{tag: "s"}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("p"), t0)
	if err := c.VerifyStructural(); err != nil {
		t.Fatalf("VerifyStructural: %v", err)
	}
}
