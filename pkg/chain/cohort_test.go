package chain

import (
	"errors"
	"testing"
)

// ===== Pillar 2: kat (R151 KAT-1 invariant) =====

func TestKAT1_HMACSHA256HexPinned(t *testing.T) {
	// R145.C FIREWALL-TEST-DISCIPLINE pin. Drift here is a cohort-
	// breaking change that MUST coincide with a MarkVersion bump.
	want := "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"
	if KAT1HMACSHA256Hex != want {
		t.Fatalf("KAT1HMACSHA256Hex drift:\n  got:  %s\n  want: %s", KAT1HMACSHA256Hex, want)
	}
}

func TestKAT1_PublishedMarkPinned(t *testing.T) {
	want := "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg"
	if KAT1PublishedMark != want {
		t.Fatalf("KAT1PublishedMark drift:\n  got:  %s\n  want: %s", KAT1PublishedMark, want)
	}
	if len(KAT1PublishedMark) != 62 {
		t.Fatalf("KAT1PublishedMark len: got %d, want 62", len(KAT1PublishedMark))
	}
}

func TestKAT1_CanonicalInputShape(t *testing.T) {
	in := KAT1CanonicalInput()
	if len(in) != KAT1InputLen {
		t.Fatalf("CanonicalInput len: got %d, want %d", len(in), KAT1InputLen)
	}
	if in[0] != MirrorMarkVersion {
		t.Fatalf("CanonicalInput[0]: got 0x%02x, want 0x%02x", in[0], MirrorMarkVersion)
	}
	for i := 1; i < KAT1InputLen; i++ {
		if in[i] != 0x00 {
			t.Fatalf("CanonicalInput[%d]: got 0x%02x, want 0x00", i, in[i])
		}
	}
}

func TestKAT1_CanonicalKeyEmpty(t *testing.T) {
	if got := KAT1CanonicalKey(); len(got) != 0 {
		t.Fatalf("CanonicalKey len: got %d, want 0", len(got))
	}
}

func TestKAT1_CorpusSHAZero(t *testing.T) {
	got := KAT1CorpusSHA()
	for i, b := range got {
		if b != 0 {
			t.Fatalf("CorpusSHA[%d]: got 0x%02x, want 0x00", i, b)
		}
	}
}

func TestAssertKAT1Parity_Ok(t *testing.T) {
	if err := AssertKAT1Parity(); err != nil {
		t.Fatalf("AssertKAT1Parity: %v", err)
	}
}

// ===== Pillar 3: honest (R143 LOUD-ONCE) =====

func TestLoudOnce_FiresExactlyOnce(t *testing.T) {
	o := NewLoudOnce()
	if !o.TryFire() {
		t.Fatalf("TryFire #1: got false, want true")
	}
	if o.TryFire() {
		t.Fatalf("TryFire #2: got true, want false")
	}
	if o.TryFire() {
		t.Fatalf("TryFire #3: got true, want false")
	}
}

func TestLoudOnce_HasFiredTransition(t *testing.T) {
	o := NewLoudOnce()
	if o.HasFired() {
		t.Fatalf("HasFired before TryFire: got true, want false")
	}
	o.TryFire()
	if !o.HasFired() {
		t.Fatalf("HasFired after TryFire: got false, want true")
	}
}

func TestLoudOnce_ResetReArms(t *testing.T) {
	// Test-only reset helper. Production code never resets a LoudOnce.
	o := NewLoudOnce()
	o.TryFire()
	o.reset()
	if !o.TryFire() {
		t.Fatalf("TryFire after reset: got false, want true")
	}
}

// ===== Pillar 4: legal (R166 LIABILITY-FOOTER) =====

func TestLegal_LiabilityFooterPresent(t *testing.T) {
	if LiabilityFooter == "" {
		t.Fatalf("LiabilityFooter is empty")
	}
	// Honest-default sentinel "NOT YET" MUST be present.
	if !contains(LiabilityFooter, "NOT YET") {
		t.Fatalf("LiabilityFooter missing 'NOT YET' sentinel: %q", LiabilityFooter)
	}
}

func TestLegal_ReviewedByCounselHonestDefaultFalse(t *testing.T) {
	if ReviewedByCounsel {
		t.Fatalf("ReviewedByCounsel: SDK MUST default to false (R166 honest-default)")
	}
}

func TestLegal_LibraryRecommendsHostActsPresent(t *testing.T) {
	if LibraryRecommendsHostActs == "" {
		t.Fatalf("LibraryRecommendsHostActs is empty")
	}
}

// ===== Pillar 5: manifest (self-description) =====

func TestManifest_NameAndVersionPinned(t *testing.T) {
	m := Manifest()
	if m.Name != "limitless-audit-chain" {
		t.Fatalf("Manifest.Name: got %q, want %q", m.Name, "limitless-audit-chain")
	}
	if m.Version != SDKVersion {
		t.Fatalf("Manifest.Version: got %q, want %q", m.Version, SDKVersion)
	}
}

func TestManifest_KAT1DigestMatchesAnchor(t *testing.T) {
	m := Manifest()
	if m.KAT1Digest != KAT1HMACSHA256Hex {
		t.Fatalf("Manifest.KAT1Digest drift: got %s, want %s", m.KAT1Digest, KAT1HMACSHA256Hex)
	}
}

func TestManifest_WireFormatDescribed(t *testing.T) {
	m := Manifest()
	if !contains(m.WireFormat, "v1 Mirror-Mark") {
		t.Fatalf("Manifest.WireFormat missing 'v1 Mirror-Mark': %q", m.WireFormat)
	}
}

// ===== Pillar 1: mirrormark constants pinned =====

func TestMirrorMark_ConstantsByteIdentical(t *testing.T) {
	if MirrorMarkPrefix != "lore@v1:" {
		t.Fatalf("MarkPrefix drift: %q", MirrorMarkPrefix)
	}
	if MirrorMarkVersion != 0x01 {
		t.Fatalf("MarkVersion drift: 0x%02x", MirrorMarkVersion)
	}
	if MirrorMarkCorpusPrefixLen != 8 {
		t.Fatalf("MarkCorpusPrefixLen drift: %d", MirrorMarkCorpusPrefixLen)
	}
	if MirrorMarkBodyLen != 40 {
		t.Fatalf("MarkBodyLen drift: %d", MirrorMarkBodyLen)
	}
}

// ===== KAT1 drift detection =====

func TestErrKAT1Drift_TypedSentinel(t *testing.T) {
	// Confirm the sentinel error is exported + matches errors.Is.
	err := ErrKAT1Drift
	if !errors.Is(err, ErrKAT1Drift) {
		t.Fatalf("ErrKAT1Drift does not match itself via errors.Is")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
