package firewall

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestIsCanonicalSBoundary(t *testing.T) {
	mk := func(s *[32]byte) []byte {
		sig := make([]byte, 64)
		copy(sig[32:], s[:])
		return sig
	}
	// L little-endian.
	l := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	if isCanonicalS(mk(&l)) {
		t.Fatal("S = L must be refused")
	}
	lm1 := l
	lm1[0]--
	if !isCanonicalS(mk(&lm1)) {
		t.Fatal("S = L-1 must be accepted")
	}
	lp1 := l
	lp1[0]++
	if isCanonicalS(mk(&lp1)) {
		t.Fatal("S = L+1 must be refused")
	}
	if isCanonicalS(make([]byte, 63)) || isCanonicalS(make([]byte, 65)) {
		t.Fatal("wrong length must be refused")
	}
}

// The sig-non-canonical-s vector is refused by our own check before the library is called; this
// also records whether crypto/ed25519 would have refused it alone.
func TestNonCanonicalSVectorRefusedByOurCheck(t *testing.T) {
	v := loadVectors(t)
	for _, raw := range v.Bundle {
		var c struct {
			Name   string   `json:"name"`
			Served string   `json:"served"`
			Pinned []keyRow `json:"pinned"`
		}
		if err := json.Unmarshal(raw, &c); err != nil || c.Name != "sig-non-canonical-s" {
			continue
		}
		var env struct{ Payload, Sig string }
		if err := json.Unmarshal([]byte(c.Served), &env); err != nil {
			t.Fatal(err)
		}
		sig, ok1 := fromBase64URL(env.Sig)
		payload, ok2 := fromBase64URL(env.Payload)
		pub, ok3 := fromBase64URL(c.Pinned[0].Pub)
		if !ok1 || !ok2 || !ok3 {
			t.Fatal("bad vector encoding")
		}
		if isCanonicalS(sig) {
			t.Fatal("vector S is canonical; the row would not prove anything")
		}
		msg := append([]byte(policySignatureDomain), payload...)
		t.Logf("crypto/ed25519 alone accepts the malleated signature: %v (our check refuses it either way)",
			ed25519.Verify(ed25519.PublicKey(pub), msg, sig))
		return
	}
	t.Fatal("vector missing")
}

func TestPinnedKeysAreConsistent(t *testing.T) {
	for _, k := range append(append([]Key{}, PinnedPolicyKeys...), PinnedSessionKeys...) {
		if !keyIsConsistent(k) {
			t.Fatalf("pinned key %s: kid is not the hash of its public key", k.Kid)
		}
		if pub, ok := fromBase64URL(k.Pub); !ok || len(pub) != 32 {
			t.Fatalf("pinned key %s pub is not 32 bytes", k.Kid)
		}
	}
}
