package certchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A leaf certifying a small-order Ed25519 key is refused, as jwk and
// COSE_Key parsing refuse one; an ordinary Ed25519 key verifies.
func TestVerifyChains_SmallOrderEd25519Leaf(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	issue := func(pub ed25519.PublicKey) []byte {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}, root, pub, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 1 // the identity point: small order
	if _, _, err := VerifyChains([][]byte{issue(identity)}, roots); err == nil {
		t.Error("a leaf with a small-order Ed25519 key verified")
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyChains([][]byte{issue(pub)}, roots); err != nil {
		t.Errorf("a leaf with an ordinary Ed25519 key: %v", err)
	}
}
