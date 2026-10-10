package jwk_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// A small-order Ed25519 key is refused: anyone can sign for it. The
// identity key verifies R = identity, S = 0 for any message.
func TestPublicKey_RefusesSmallOrderEd25519(t *testing.T) {
	identity := append([]byte{1}, make([]byte, 31)...)
	forged := append(append([]byte(nil), identity...), make([]byte, 32)...)
	if !ed25519.Verify(identity, []byte("any message"), forged) {
		t.Fatal("test setup: the identity key's forgery doesn't verify")
	}
	withSign := append([]byte(nil), identity...)
	withSign[31] |= 0x80
	for name, x := range map[string][]byte{"identity": identity, "identity, sign bit set": withSign, "zero": make([]byte, 32)} {
		k := jwk.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(x)}
		if _, err := k.PublicKey(); err == nil || !strings.Contains(err.Error(), "small order") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.IsSmallOrderEd25519(pub) {
		t.Error("a generated key counted as small order")
	}
	if _, err := (jwk.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}).PublicKey(); err != nil {
		t.Errorf("a generated key: %v", err)
	}
}
