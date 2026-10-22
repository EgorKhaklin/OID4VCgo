package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// With RequireIssuerName, a received SD-JWT VC's iss must name the
// certificate that signed it: another issuer's certificate under the
// same trusted root can't issue in this issuer's name. Without it, the
// default, iss isn't checked against the certificate (SD-JWT VC §2.5).
func TestVerifyIssuedCredential_BindsIssToLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(certURI, iss string) string {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(certURI)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		exp := time.Now().Add(time.Hour).Unix()
		credential, _, err := sdjwtvc.Issue(key, jose.ES256, sdjwtvc.Claims{
			Iss: iss, VCT: issuedVCT, Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}
	requireName := true
	verify := func(credential string) error {
		_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: oid4vci.CredentialConfigurationMetadata{Format: sdjwtvc.CredentialFormat, VCT: issuedVCT, CryptographicBindingMethodsSupported: []string{"jwk"}},
			Credential:    credential, HolderKey: &holder.PublicKey, IssuerRoots: roots, RequireIssuerName: requireName,
		})
		return err
	}
	if err := verify(issue("https://issuer-a.example", "https://issuer-a.example")); err != nil {
		t.Errorf("the issuer's own certificate: %v", err)
	}
	if err := verify(issue("https://issuer-b.example", "https://issuer-a.example")); err == nil {
		t.Error("accepted a credential in issuer A's name signed by issuer B's certificate")
	}
	if err := verify(issue("https://issuer-b.example", "")); err == nil {
		t.Error("accepted a credential naming no issuer, with RequireIssuerName set")
	}
	requireName = false
	if err := verify(issue("https://issuer-b.example", "https://issuer-a.example")); err != nil {
		t.Errorf("by default, iss isn't checked against the certificate: %v", err)
	}
}

// With CredentialIssuer, a received SD-JWT VC that names an issuer must
// name the one the Wallet requested it from, exactly, whichever
// certificate under IssuerRoots signed it: an issuer can't pass off
// another's credential as its own. One naming none has nothing to
// check, and without CredentialIssuer, the default, iss isn't checked.
func TestVerifyIssuedCredential_BindsIssToCredentialIssuer(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	issue := func(iss string) string {
		t.Helper()
		exp := time.Now().Add(time.Hour).Unix()
		credential, _, err := sdjwtvc.Issue(key, jose.ES256, sdjwtvc.Claims{
			Iss: iss, VCT: issuedVCT, Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}
	for _, tc := range []struct {
		iss, credentialIssuer string
		ok                    bool
	}{
		{"https://issuer-a.example", "https://issuer-a.example", true},
		{"https://issuer-a.example", "https://issuer-b.example", false},
		{"https://issuer-a.example", "https://Issuer-A.example", false},
		{"https://issuer-a.example", "https://issuer-a.example/", false},
		{"", "https://issuer-a.example", true},
		{"https://issuer-a.example", "", true},
	} {
		_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: oid4vci.CredentialConfigurationMetadata{Format: sdjwtvc.CredentialFormat, VCT: issuedVCT, CryptographicBindingMethodsSupported: []string{"jwk"}},
			Credential:    issue(tc.iss), HolderKey: &holder.PublicKey, IssuerRoots: roots, CredentialIssuer: tc.credentialIssuer,
		})
		if (err == nil) != tc.ok {
			t.Errorf("iss %q, CredentialIssuer %q: %v, want ok=%v", tc.iss, tc.credentialIssuer, err, tc.ok)
		}
	}
}
