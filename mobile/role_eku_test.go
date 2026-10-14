package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func ekuCert(t *testing.T, standard []x509.ExtKeyUsage, custom []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "eku test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: standard, UnknownExtKeyUsage: custom,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The leaf's extended key usage extension is read as is, so a standard
// usage (which Go files under ExtKeyUsage) and a private one (under
// UnknownExtKeyUsage) both match.
func TestRequireEKU(t *testing.T) {
	private := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	for name, tc := range map[string]struct {
		cert   *x509.Certificate
		oid    string
		wantOK bool
	}{
		"standard (clientAuth)": {ekuCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil), "1.3.6.1.5.5.7.3.2", true},
		"private":               {ekuCert(t, nil, []asn1.ObjectIdentifier{private}), "1.3.6.1.4.1.99999.1", true},
		"another usage":         {ekuCert(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil), "1.3.6.1.5.5.7.3.2", false},
		"no usage at all":       {ekuCert(t, nil, nil), "1.3.6.1.5.5.7.3.2", false},
	} {
		policy, err := roleEKU("verifier_require_eku", tc.oid)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy(tc.cert, nil); (err == nil) != tc.wantOK {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.wantOK)
		}
	}
	for _, bad := range []string{"1", "1.x.3", "-1.2"} {
		if _, err := roleEKU("verifier_require_eku", bad); err == nil {
			t.Errorf("%q accepted as an OID", bad)
		}
	}
}

// Outside development, verifier or registrar roots sharing an anchor
// with another role's need that role's EKU.
func TestCheckRoleRoots(t *testing.T) {
	shared := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekuCert(t, nil, nil).Raw}))
	other := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ekuCert(t, nil, nil).Raw}))
	for name, tc := range map[string]struct {
		cfg     config
		refused string
	}{
		"separate anchors":               {cfg: config{IssuerRoots: other, VerifierRoots: shared}},
		"verifier shares with issuer":    {cfg: config{IssuerRoots: shared, VerifierRoots: shared}, refused: "verifier_require_eku"},
		"registrar shares with verifier": {cfg: config{VerifierRoots: shared, VerifierRequireEKU: "1.2.3", RegistrarRoots: shared}, refused: "registrar_require_eku"},
		"both have EKUs":                 {cfg: config{VerifierRoots: shared, VerifierRequireEKU: "1.2.3", RegistrarRoots: shared, RegistrarRequireEKU: "1.2.4"}},
		"development":                    {cfg: config{IssuerRoots: shared, VerifierRoots: shared, Development: true}},
	} {
		err := checkRoleRoots(tc.cfg)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused naming %s", name, err, tc.refused)
		}
	}
}
