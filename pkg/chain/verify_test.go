package chain

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// ===== MirrorMarkSigner / MirrorMarkVerifier round-trip =====

func TestMirrorMarkSigner_NilReceiverError(t *testing.T) {
	var s *MirrorMarkSigner
	_, err := s.Sign([]byte("x"))
	if !errors.Is(err, ErrMirrorMarkNilSigner) {
		t.Fatalf("got %v, want ErrMirrorMarkNilSigner", err)
	}
}

func TestMirrorMarkSigner_EmitsCanonicalPrefix(t *testing.T) {
	signer := &MirrorMarkSigner{
		CorpusSHA: [sha256.Size]byte{},
		Key:       []byte("test-key"),
	}
	mark, err := signer.Sign([]byte("canonical-payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(mark) < len(MirrorMarkPrefix) || mark[:len(MirrorMarkPrefix)] != MirrorMarkPrefix {
		t.Fatalf("Sign output missing canonical prefix: %q", mark)
	}
	// Total length: 8 (prefix) + 54 (base64url body) = 62 chars.
	if len(mark) != 62 {
		t.Fatalf("Sign output length: got %d, want 62", len(mark))
	}
}

func TestMirrorMarkVerifier_AcceptsSelfSigned(t *testing.T) {
	corpusSHA := [sha256.Size]byte{}
	for i := range corpusSHA {
		corpusSHA[i] = byte(i)
	}
	key := []byte("test-key")
	signer := &MirrorMarkSigner{CorpusSHA: corpusSHA, Key: key}
	verifier := MirrorMarkVerifier(corpusSHA, key)

	c := NewChain()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	_, err := c.AppendSigned(signer, SignerID("delve"), []byte("payload-1"), now)
	if err != nil {
		t.Fatalf("AppendSigned: %v", err)
	}
	_, err = c.AppendSigned(signer, SignerID("grounded"), []byte("payload-2"), now.Add(time.Second))
	if err != nil {
		t.Fatalf("AppendSigned#2: %v", err)
	}
	if err := c.Verify(verifier); err != nil {
		t.Fatalf("Verify under MirrorMarkVerifier: %v", err)
	}
}

func TestMirrorMarkVerifier_RejectsWrongKey(t *testing.T) {
	corpusSHA := [sha256.Size]byte{}
	signer := &MirrorMarkSigner{CorpusSHA: corpusSHA, Key: []byte("signing-key")}
	// Verifier uses a DIFFERENT key.
	verifier := MirrorMarkVerifier(corpusSHA, []byte("wrong-key"))

	c := NewChain()
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("x"), time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	err := c.Verify(verifier)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("got %v, want ErrSignatureMismatch", err)
	}
}

func TestMirrorMarkVerifier_RejectsCorpusMismatch(t *testing.T) {
	corpusA := [sha256.Size]byte{}
	corpusA[0] = 0xAA
	corpusB := [sha256.Size]byte{}
	corpusB[0] = 0xBB
	signer := &MirrorMarkSigner{CorpusSHA: corpusA, Key: []byte("k")}
	verifier := MirrorMarkVerifier(corpusB, []byte("k"))

	c := NewChain()
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("x"), time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC))

	err := c.Verify(verifier)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("got %v, want ErrSignatureMismatch wrapping ErrMirrorMarkCorpusMismatch", err)
	}
	if !errors.Is(err, ErrMirrorMarkCorpusMismatch) {
		t.Fatalf("got %v, want ErrSignatureMismatch wrapping ErrMirrorMarkCorpusMismatch", err)
	}
}

func TestMirrorMarkVerifier_RejectsUnknownVersion(t *testing.T) {
	corpusSHA := [sha256.Size]byte{}
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       "notamark", // no lore@v1: prefix
	})
	verifier := MirrorMarkVerifier(corpusSHA, []byte("k"))
	err := c.Verify(verifier)
	if !errors.Is(err, ErrMirrorMarkUnknownVersion) {
		t.Fatalf("got %v, want chain to wrap ErrMirrorMarkUnknownVersion", err)
	}
}

func TestMirrorMarkVerifier_RejectsMalformedBody(t *testing.T) {
	corpusSHA := [sha256.Size]byte{}
	c := NewChain()
	c.Append(Receipt{
		PrevReceiptHash: GenesisPrevHash,
		PayloadHash:     mkPayloadHash("x"),
		SignerID:        SignerID("delve"),
		Timestamp:       time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Signature:       MirrorMarkPrefix + "this-is-not-base64url-of-the-right-length",
	})
	verifier := MirrorMarkVerifier(corpusSHA, []byte("k"))
	err := c.Verify(verifier)
	if !errors.Is(err, ErrMirrorMarkMalformed) {
		t.Fatalf("got %v, want chain to wrap ErrMirrorMarkMalformed", err)
	}
}

func TestVerify_NilVerifierAcceptsStructure(t *testing.T) {
	// Verify(nil) is structural-only and accepts well-shaped chains.
	c := NewChain()
	signer := &fixedHMACSigner{tag: "n"}
	t0 := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	_, _ = c.AppendSigned(signer, SignerID("delve"), []byte("p"), t0)
	if err := c.Verify(nil); err != nil {
		t.Fatalf("Verify(nil) on well-shaped chain: %v", err)
	}
}

// ===== KAT-1 byte-identity preservation via MirrorMarkSigner =====

func TestMirrorMarkSigner_KAT1MatchesPublishedMark(t *testing.T) {
	// The cohort-canonical KAT-1 verification: signing the EMPTY
	// payload with the canonical corpus SHA (32 zero bytes) and the
	// canonical empty key MUST produce the cohort-published Mark
	// `lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg`.
	signer := &MirrorMarkSigner{
		CorpusSHA: KAT1CorpusSHA(),
		Key:       KAT1CanonicalKey(),
	}
	got, err := signer.Sign(nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != KAT1PublishedMark {
		t.Fatalf("KAT-1 published mark drift:\n  got:  %s\n  want: %s", got, KAT1PublishedMark)
	}
}
