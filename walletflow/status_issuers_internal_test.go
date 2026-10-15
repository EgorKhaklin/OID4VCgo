package walletflow

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
	"github.com/idfoundry/oid4vcgo/statuslist"
)

func namedCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, uri string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(uri)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		URIs: []*url.URL{u},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A credential's status list may be signed by its issuer, or by one of
// the Status Issuers Config.StatusIssuers names for that issuer, and no
// one else.
func TestStatusOptionsFor(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	const issuerA, statusIssuer, issuerB = "https://issuer-a.example", "https://status.example", "https://issuer-b.example"
	a, status, b := namedCert(t, ca, caKey, issuerA), namedCert(t, ca, caKey, statusIssuer), namedCert(t, ca, caKey, issuerB)

	// Without Status Issuers, the token must be the issuer's.
	if opts := statusOptionsFor(statuslist.VerifyOptions{}, issuerA, nil); opts.Issuer != issuerA || opts.LeafPolicy != nil {
		t.Errorf("no Status Issuers: %+v, want Issuer set and no LeafPolicy", opts)
	}
	opts := statusOptionsFor(statuslist.VerifyOptions{}, issuerA, []string{statusIssuer})
	for name, tc := range map[string]struct {
		leaf *x509.Certificate
		ok   bool
	}{
		"the issuer":        {a, true},
		"its Status Issuer": {status, true},
		"another issuer":    {b, false},
	} {
		if err := opts.LeafPolicy(tc.leaf, nil); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}
