package firewall

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

// The Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
var groupOrderL = func() *big.Int {
	l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
}()

// fromBase64URL is the strict unpadded base64url decoder: no padding, no characters outside the
// alphabet, no non-zero trailing bits, no length of 1 mod 4.
func fromBase64URL(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// KidOfPublicKey is the first 8 bytes of SHA-256(raw public key) as 16 lower-case hex characters.
func KidOfPublicKey(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:8])
}

// isCanonicalS reports whether the S half of a 64-byte Ed25519 signature (little-endian) is below
// the group order L. RFC 8032 requires it. It is checked here, before the library call and
// independently of the library, so a malleated signature is never accepted (vector
// sig-non-canonical-s).
func isCanonicalS(sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	var be [32]byte
	for i := 0; i < 32; i++ {
		be[31-i] = sig[32+i]
	}
	return new(big.Int).SetBytes(be[:]).Cmp(groupOrderL) < 0
}

// verifyDomain verifies domain || payload under a pinned or token key: the key must be Ed25519,
// the signature 64 bytes with a canonical S. Never panics; false on any failure.
func verifyDomain(key Key, domain string, payload, sig []byte) bool {
	if key.Alg != "Ed25519" || !isCanonicalS(sig) {
		return false
	}
	pub, ok := fromBase64URL(key.Pub)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return false
	}
	msg := make([]byte, 0, len(domain)+len(payload))
	msg = append(msg, domain...)
	msg = append(msg, payload...)
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// keyIsConsistent: the key's declared kid is the real kid of its public key (placeholders are not).
func keyIsConsistent(key Key) bool {
	pub, ok := fromBase64URL(key.Pub)
	return ok && len(pub) == ed25519.PublicKeySize && KidOfPublicKey(pub) == key.Kid
}

// PinnedPolicyKeys are the production bundle keys, current and next (the same keys as
// packages/protocol/src/policy/pinned-keys.ts). Test keys are never pinned here; tests pass their own.
var PinnedPolicyKeys = []Key{
	{Kid: "dc43cba74b531a58", Alg: "Ed25519", Pub: "9aawK32yAp7kIuAaLJYE7Y5W40w0TjJxuaoqSe2NNuA", NotAfter: 4102444800},
	{Kid: "79105aac0b45dd0c", Alg: "Ed25519", Pub: "ZdstW3eqBJ7TpwPkudQKVd_g2wNqUsGSMUKOzXpCF9M", NotAfter: 4102444800},
}

// PinnedSessionKeys are the production session signing keys, current and next. The session keys
// actually used to verify a token come from the verified bundle's tokenKeys, which the pinned bundle key signs.
var PinnedSessionKeys = []Key{
	{Kid: "cd7e0df68b55c9ce", Alg: "Ed25519", Pub: "WlDajxX_FgHup2I3O4qlujgfgBhZdwBIhs5dqqDrXwM", NotAfter: 4102444800},
	{Kid: "e3386ef628ea8430", Alg: "Ed25519", Pub: "oDW6PsK0hRuxprSto16YCyuY_tcZcI4aH1TyhUfD6Ms", NotAfter: 4102444800},
}

// testPolicyKeys are the public TEST bundle keys of packages/protocol/test-vectors/policy.json
// (their seeds are public). New refuses them unless the site key is non-canonical and the API
// base is loopback (Ruling 13).
var testPolicyKeys = []Key{
	{Kid: "3d75ce3772a93b6e", Alg: "Ed25519", Pub: "mkgsn6TedEnh1On988cT8ujJnUMDF1SaeTPCjRaasF0", NotAfter: 4102444800},
	{Kid: "30c94a60406a6ea6", Alg: "Ed25519", Pub: "nvfcYJX2dOZjA0fjvFW_XkspaP7RVu5_Shw-muGLXj0", NotAfter: 4102444800},
	{Kid: "990ae9db448cb6fd", Alg: "Ed25519", Pub: "JMmCSFznt-U2yeFyfLpLykQcWQoyuZXv701HS8xeFxw", NotAfter: 1700000000},
}

// TestPolicyKeys returns a copy of the public TEST bundle keys, for conformance runs only. Passing
// them to New is accepted only for a non-canonical site key (e.g. rgpk_conformance) with a
// loopback API base.
func TestPolicyKeys() []Key { return append([]Key(nil), testPolicyKeys...) }

func isTestKey(k Key) bool {
	for _, t := range testPolicyKeys {
		if k.Kid == t.Kid || k.Pub == t.Pub {
			return true
		}
	}
	return false
}
