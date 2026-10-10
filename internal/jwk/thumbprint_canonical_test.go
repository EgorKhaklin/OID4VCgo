package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// One key has one thumbprint, however its members are written:
// base64url decoding forgives a line break and stray trailing bits.
func TestThumbprint_NonCanonicalEncodings(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonical.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	// 32 bytes is 43 base64url characters, the last carrying 2 unused
	// bits: flip one.
	last := strings.Index("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", canonical.X[42:])
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	variants := map[string]jwk.JWK{
		"a line break":  {Kty: "EC", Crv: "P-256", X: canonical.X[:20] + "\n" + canonical.X[20:], Y: canonical.Y},
		"trailing bits": {Kty: "EC", Crv: "P-256", X: canonical.X[:42] + string(alphabet[last^1]), Y: canonical.Y},
	}
	for name, v := range variants {
		if _, err := v.PublicKey(); err != nil {
			t.Fatalf("%s: test setup: doesn't decode: %v", name, err)
		}
		if got, err := v.Thumbprint(); err != nil || got != want {
			t.Errorf("%s: thumbprint %s, %v; want %s", name, got, err, want)
		}
		raw, _ := json.Marshal(v)
		if ok, err := jwk.Matches(raw, &key.PublicKey); err != nil || !ok {
			t.Errorf("%s: Matches = %v, %v; want the same key", name, ok, err)
		}
	}
}
