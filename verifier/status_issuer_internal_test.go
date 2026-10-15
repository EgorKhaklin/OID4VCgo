package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A credential's status list is bound to its issuer: its iss, or
// without one the URI its x5c leaf names.
func TestVerifiedCredential_IssuerName(t *testing.T) {
	ca, caKey := testcert.CA(t, "root")
	unnamed, _ := testcert.Leaf(t, "issuer", ca, caKey)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{{Scheme: "https", Host: "issuer-a.example"}},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		vc   VerifiedCredential
		want string
	}{
		"its iss":            {VerifiedCredential{Claims: map[string]any{"iss": "https://issuer-a.example"}}, "https://issuer-a.example"},
		"no iss: leaf's URI": {VerifiedCredential{Claims: map[string]any{}, IssuerChain: [][]byte{der}}, "https://issuer-a.example"},
		"no iss, no URI":     {VerifiedCredential{Claims: map[string]any{}, IssuerChain: [][]byte{unnamed.Raw}}, ""},
		"no iss, no chain":   {VerifiedCredential{Claims: map[string]any{}}, ""},
	} {
		if got := tc.vc.issuerName(); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}
