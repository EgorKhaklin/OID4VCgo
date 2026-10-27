package certchain

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// SignerKeyIsEdDSA tells the two signer keys this module verifies
// apart, and names what's wrong with any other.
func TestSignerKeyIsEdDSA(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		pub   any
		eddsa bool
		want  string
	}{
		"P-256":   {&p256.PublicKey, false, ""},
		"Ed25519": {edPub, true, ""},
		"P-384":   {&p384.PublicKey, false, "an ECDSA key on P-384, but only P-256 (ES256) is supported"},
		"RSA":     {&rsa.PublicKey{}, false, "unsupported key type *rsa.PublicKey"},
	} {
		eddsa, err := SignerKeyIsEdDSA(tc.pub)
		if tc.want == "" && (err != nil || eddsa != tc.eddsa) || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, %v; want %v, %q", name, eddsa, err, tc.eddsa, tc.want)
		}
	}
}
