package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: issueTestCert(t, name, true, &key.PublicKey, nil, key), key: key}
}

func issueTestCert(t *testing.T, name string, isCA bool, pub *ecdsa.PublicKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func (ca testCA) leaf(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return issueTestCert(t, name, false, &key.PublicKey, ca.cert, ca.key)
}

// A revocation list's signer must be under the CA that signed the
// document signer, or the Certificate the MSO's status names (ISO/IEC
// 18013-5 §12.3.6), not just under any CA the reader trusts.
func TestStatusTrust(t *testing.T) {
	iaca, other := newTestCA(t, "IACA"), newTestCA(t, "another IACA")
	ds := iaca.leaf(t, "document signer")
	statusSigner, foreignSigner := iaca.leaf(t, "status signer"), other.leaf(t, "another status signer")

	trust, err := StatusTrust(&StatusListRef{URI: "https://status.example/1"}, []*x509.Certificate{ds})
	if err != nil || trust.Roots != nil || trust.LeafPolicy == nil {
		t.Fatalf("StatusTrust = %+v, %v; want a LeafPolicy", trust, err)
	}
	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		ok    bool
	}{
		"under the IACA that signed the DS": {[]*x509.Certificate{statusSigner, iaca.cert}, true},
		"under another IACA":                {[]*x509.Certificate{foreignSigner, other.cert}, false},
	} {
		if err := trust.LeafPolicy(tc.chain[0], [][]*x509.Certificate{tc.chain}); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
	// A document signer path that carries its IACA binds to that IACA.
	withAnchor, err := StatusTrust(nil, []*x509.Certificate{ds, iaca.cert})
	if err != nil || withAnchor.LeafPolicy(statusSigner, [][]*x509.Certificate{{statusSigner, iaca.cert}}) != nil ||
		withAnchor.LeafPolicy(foreignSigner, [][]*x509.Certificate{{foreignSigner, other.cert}}) == nil {
		t.Errorf("a path with its anchor: %v", err)
	}

	// The MSO's Certificate is the trust point instead.
	named, err := StatusTrust(&StatusListRef{URI: "https://status.example/1", Certificate: other.cert.Raw}, []*x509.Certificate{ds})
	if err != nil || named.Roots == nil || named.LeafPolicy != nil {
		t.Fatalf("with a Certificate: %+v, %v; want Roots", named, err)
	}
	if _, err := foreignSigner.Verify(x509.VerifyOptions{Roots: named.Roots}); err != nil {
		t.Errorf("a signer under the named Certificate doesn't verify to Roots: %v", err)
	}
	if _, err := statusSigner.Verify(x509.VerifyOptions{Roots: named.Roots}); err == nil {
		t.Error("a signer under the DS's IACA verifies to the named Certificate's Roots")
	}

	if _, err := StatusTrust(nil, nil); err == nil {
		t.Error("no document signer path and no Certificate: accepted")
	}
	if _, err := StatusTrust(&StatusListRef{Certificate: []byte("junk")}, nil); err == nil {
		t.Error("a Certificate that isn't one: accepted")
	}
}

// IssuerAuthStatus reads an issued mdoc's status and x5chain back.
func TestIssuerAuthStatus(t *testing.T) {
	f := newFixture(t)
	status, chain, err := IssuerAuthStatus(f.signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || string(chain[0].Raw) != string(f.cert) {
		t.Errorf("chain = %d certificates, want the fixture's", len(chain))
	}
	_ = status
	if _, _, err := IssuerAuthStatus(IssuerSigned{IssuerAuth: []byte("junk")}); err == nil {
		t.Error("junk IssuerAuth: accepted")
	}
}
