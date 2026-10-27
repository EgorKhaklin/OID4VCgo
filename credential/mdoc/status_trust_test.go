package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
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

// intermediate is a CA under ca, named name.
func (ca testCA) intermediate(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: issueTestCert(t, name, true, &key.PublicKey, ca.cert, ca.key), key: key}
}

// Under intermediates, the status list's signer is bound to the one
// that signed the document signer, not to the root above it: another
// intermediate of the same root (another issuer's) can't decide this
// issuer's status.
func TestStatusTrust_BindsTheDocumentSignersIssuer(t *testing.T) {
	root := newTestCA(t, "national root")
	caA, caB := root.intermediate(t, "issuer A CA"), root.intermediate(t, "issuer B CA")
	ds := caA.leaf(t, "issuer A document signer")
	signerA, signerB := caA.leaf(t, "issuer A status signer"), caB.leaf(t, "issuer B status signer")
	// Issuer A's CA certified again under its key: a cross-certificate.
	caAAgain := issueTestCert(t, "issuer A CA", true, &caA.key.PublicKey, root.cert, root.key)

	for name, path := range map[string][]*x509.Certificate{
		"without the anchor": {ds, caA.cert},
		"with the anchor":    {ds, caA.cert, root.cert},
	} {
		trust, err := StatusTrust(nil, path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for chainName, tc := range map[string]struct {
			chain []*x509.Certificate
			ok    bool
		}{
			"under the CA that signed the DS":     {[]*x509.Certificate{signerA, caA.cert, root.cert}, true},
			"under that CA's cross-certificate":   {[]*x509.Certificate{signerA, caAAgain, root.cert}, true},
			"that CA itself":                      {[]*x509.Certificate{caA.cert, root.cert}, true},
			"under a sibling CA of the same root": {[]*x509.Certificate{signerB, caB.cert, root.cert}, false},
			"the root itself, above the DS's CA":  {[]*x509.Certificate{root.cert}, false},
		} {
			if err := trust.LeafPolicy(tc.chain[0], [][]*x509.Certificate{tc.chain}); (err == nil) != tc.ok {
				t.Errorf("%s, %s: %v, want ok = %v", name, chainName, err, tc.ok)
			}
		}
	}

	// A path whose second certificate didn't sign the document signer
	// isn't one.
	if _, err := StatusTrust(nil, []*x509.Certificate{ds, caB.cert}); err == nil {
		t.Error("a path whose second certificate didn't sign the document signer: accepted")
	}
}

// IdentifierListTrust applies StatusTrust's rule (tested there) to an
// identifier list's reference: its Certificate pins the signer.
func TestIdentifierListTrust(t *testing.T) {
	other := newTestCA(t, "another IACA")
	pinned, err := IdentifierListTrust(&IdentifierListRef{Certificate: other.cert.Raw}, nil)
	if err != nil || pinned.Roots == nil {
		t.Fatalf("with a Certificate: %+v, %v; want Roots", pinned, err)
	}
	if _, err := IdentifierListTrust(nil, nil); err == nil {
		t.Error("no document signer path and no Certificate: accepted")
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
	// Issue won't sign with an x5chain that isn't a certificate, so the
	// fixture's MSO is signed again directly.
	_, _, payload, err := cose.DecodeUnverified(f.signed.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	junkChain := f.signed
	if junkChain.IssuerAuth, err = cose.Sign(cose.ES256, f.issuerKey, cose.Headers{X5Chain: [][]byte{{1, 2, 3}}}, cose.Headers{}, payload, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssuerAuthStatus(junkChain); err == nil || !strings.Contains(err.Error(), "IssuerAuth x5chain") {
		t.Errorf("an x5chain that isn't a certificate: %v", err)
	}
}
