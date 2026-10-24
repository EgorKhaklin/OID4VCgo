package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

const (
	providerA = "https://provider-a.example.com"
	providerB = "https://provider-b.example.com"
)

// testProvider is a Wallet Provider with its own CA.
type testProvider struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func newTestProvider(t *testing.T, name string) testProvider {
	t.Helper()
	ca, caKey := testcert.CA(t, name+" CA")
	return testProvider{ca: ca, caKey: caKey}
}

// leafNaming issues a signing certificate under p's CA whose URI
// subject alternative name is uri ("" for none).
func (p testProvider) leafNaming(t *testing.T, uri string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "attestation signer"}}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	return testcert.Issue(t, tmpl, p.ca, p.caKey)
}

// keyAttestationWithIssuer is a key attestation claiming iss ("" for
// none), signed by signer with x5c holding leaf.
func keyAttestationWithIssuer(t *testing.T, signer *ecdsa.PrivateKey, leaf *x509.Certificate, iss string) attestation.KeyAttestation {
	t.Helper()
	claims := map[string]any{"iat": 1, "attested_keys": []any{map[string]any{"kty": "EC"}}}
	if iss != "" {
		claims["iss"] = iss
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"typ": attestation.TypHeader, "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)}}
	compact, err := jose.Sign(jose.ES256, signer, header, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatalf("attestation.Parse: %v", err)
	}
	return parsed
}

// twoProviderVerifiers returns, for Wallet Providers A and B under their
// own CAs, a verifier for each binding over both providers' anchors.
func twoProviderVerifiers(a, b testProvider) map[issuer.AttestationIssuerBinding]issuer.X5CAttestationVerifier {
	roots := x509.NewCertPool()
	roots.AddCert(a.ca)
	roots.AddCert(b.ca)
	return map[issuer.AttestationIssuerBinding]issuer.X5CAttestationVerifier{
		issuer.AttestationIssuerUnbound:       {Roots: roots},
		issuer.AttestationIssuerInCertificate: {Roots: roots, IssuerBinding: issuer.AttestationIssuerInCertificate},
		issuer.AttestationIssuerBoundToAnchor: {IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: []issuer.AttestationAnchor{
			{Certificate: a.ca, Issuers: []string{providerA}},
			{Certificate: b.ca, Issuers: []string{providerB}},
		}},
	}
}

// Two Wallet Providers, each under its own CA, both trusted: which
// signing certificate may sign a key attestation naming which provider,
// under each binding.
func TestX5CAttestationVerifier_IssuerBinding(t *testing.T) {
	a, b := newTestProvider(t, "provider A"), newTestProvider(t, "provider B")
	verifiers := twoProviderVerifiers(a, b)
	aLeaf, aKey := a.leafNaming(t, providerA)
	bLeaf, bKey := b.leafNaming(t, providerB)
	// Provider A's CA certifying a key in provider B's name.
	forgedLeaf, forgedKey := a.leafNaming(t, providerB)
	unnamedLeaf, unnamedKey := a.leafNaming(t, "")

	type accepted map[issuer.AttestationIssuerBinding]bool
	cases := []struct {
		name string
		key  *ecdsa.PrivateKey
		leaf *x509.Certificate
		iss  string
		want accepted
	}{
		{"A signs as A", aKey, aLeaf, providerA, accepted{0: true, 1: true, 2: true}},
		{"B signs as B", bKey, bLeaf, providerB, accepted{0: true, 1: true, 2: true}},
		{"A's certificate signs as B", aKey, aLeaf, providerB, accepted{0: true}},
		{"A's CA certifies a key naming B", forgedKey, forgedLeaf, providerB, accepted{0: true, 1: true}},
		{"no iss", aKey, aLeaf, "", accepted{0: true}},
		{"certificate names no one", unnamedKey, unnamedLeaf, providerA, accepted{0: true}},
	}
	for _, tc := range cases {
		for binding, v := range verifiers {
			pub, _, err := v.ResolveAttestationKey(context.Background(), keyAttestationWithIssuer(t, tc.key, tc.leaf, tc.iss))
			if got := err == nil; got != tc.want[binding] {
				t.Errorf("%s, binding %d: accepted = %v (err %v), want %v", tc.name, binding, got, err, tc.want[binding])
			}
			if err == nil && !tc.key.PublicKey.Equal(pub) {
				t.Errorf("%s, binding %d: resolved a key other than the leaf's", tc.name, binding)
			}
		}
	}
}

// A "dns:" iss is bound to a DNS subject alternative name.
func TestX5CAttestationVerifier_IssuerInCertificateDNSName(t *testing.T) {
	p := newTestProvider(t, "provider")
	leaf, key := testcert.Issue(t, &x509.Certificate{DNSNames: []string{"provider.example.com"}}, p.ca, p.caKey)
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	v := issuer.X5CAttestationVerifier{Roots: roots, IssuerBinding: issuer.AttestationIssuerInCertificate}
	if _, _, err := v.ResolveAttestationKey(context.Background(), keyAttestationWithIssuer(t, key, leaf, "dns:provider.example.com")); err != nil {
		t.Errorf("dns: iss naming the certificate's DNS name: %v", err)
	}
	if _, _, err := v.ResolveAttestationKey(context.Background(), keyAttestationWithIssuer(t, key, leaf, "dns:other.example.com")); err == nil {
		t.Error("accepted a dns: iss the certificate doesn't name")
	}
}

// Under AttestationIssuerBoundToAnchor, LeafPolicy still runs.
func TestX5CAttestationVerifier_BoundToAnchorRunsLeafPolicy(t *testing.T) {
	p := newTestProvider(t, "provider A")
	leaf, key := p.leafNaming(t, providerA)
	refused := errors.New("refused by policy")
	v := issuer.X5CAttestationVerifier{
		IssuerBinding: issuer.AttestationIssuerBoundToAnchor,
		Anchors:       []issuer.AttestationAnchor{{Certificate: p.ca, Issuers: []string{providerA}}},
		LeafPolicy:    func(*x509.Certificate, [][]*x509.Certificate) error { return refused },
	}
	if _, _, err := v.ResolveAttestationKey(context.Background(), keyAttestationWithIssuer(t, key, leaf, providerA)); !errors.Is(err, refused) {
		t.Errorf("err = %v, want the LeafPolicy's", err)
	}
}

// The binding reaches the Credential Endpoint: provider A's CA can't
// certify a key that attests in provider B's name.
func TestRequestCredential_KeyAttestationBoundToAnchor(t *testing.T) {
	a, b := newTestProvider(t, "provider A"), newTestProvider(t, "provider B")
	verifier := twoProviderVerifiers(a, b)[issuer.AttestationIssuerBoundToAnchor]
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.AttestationVerifier = verifier
	})
	request := func(t *testing.T, p testProvider, named, iss string) error {
		t.Helper()
		leaf, key := p.leafNaming(t, named)
		attested := testP256Key(t)
		att, err := attestation.Issue(key, jose.ES256, attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(leaf.Raw)}}, attestation.Claims{
			Issuer: iss, IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{jwkJSON(t, &attested.PublicKey)}, Nonce: f.issueNonce(t),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
			SDJWTClaims:               testSDJWTClaims(),
		})
		return err
	}
	if err := request(t, b, providerB, providerB); err != nil {
		t.Fatalf("provider B attesting as itself: %v", err)
	}
	assertIssuerError(t, request(t, a, providerB, providerB), issuer.ErrorInvalidProof)
}

// New refuses an X5CAttestationVerifier whose fields don't fit its
// IssuerBinding.
func TestNew_RefusesMisconfiguredAttestationIssuerBinding(t *testing.T) {
	p := newTestProvider(t, "provider A")
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	anchors := []issuer.AttestationAnchor{{Certificate: p.ca, Issuers: []string{providerA}}}
	cases := map[string]issuer.AttestationVerifier{
		"anchors without binding":      issuer.X5CAttestationVerifier{Roots: roots, Anchors: anchors},
		"anchors in certificate":       issuer.X5CAttestationVerifier{Roots: roots, IssuerBinding: issuer.AttestationIssuerInCertificate, Anchors: anchors},
		"bound to anchor with roots":   issuer.X5CAttestationVerifier{Roots: roots, IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: anchors},
		"bound to anchor, no anchors":  issuer.X5CAttestationVerifier{IssuerBinding: issuer.AttestationIssuerBoundToAnchor},
		"anchor without certificate":   issuer.X5CAttestationVerifier{IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: []issuer.AttestationAnchor{{Issuers: []string{providerA}}}},
		"anchor bound to no issuer":    issuer.X5CAttestationVerifier{IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: []issuer.AttestationAnchor{{Certificate: p.ca}}},
		"anchor bound to empty issuer": issuer.X5CAttestationVerifier{IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: []issuer.AttestationAnchor{{Certificate: p.ca, Issuers: []string{""}}}},
		"unknown binding":              issuer.X5CAttestationVerifier{Roots: roots, IssuerBinding: 99},
		"nil pointer":                  (*issuer.X5CAttestationVerifier)(nil),
		"pointer, misconfigured":       &issuer.X5CAttestationVerifier{IssuerBinding: issuer.AttestationIssuerBoundToAnchor},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tryCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) { deps.AttestationVerifier = v })
			if err == nil || !strings.Contains(err.Error(), "attestation_verifier") {
				t.Errorf("New: err = %v, want an attestation_verifier error", err)
			}
		})
	}
	if _, err := tryCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.AttestationVerifier = &issuer.X5CAttestationVerifier{IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: anchors}
	}); err != nil {
		t.Errorf("New with a bound *X5CAttestationVerifier: %v", err)
	}
}
