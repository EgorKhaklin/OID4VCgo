package issuer_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// X5CAttestationVerifier.Revocation refuses a key attestation signed
// under a revoked Wallet Provider certificate, under every issuer
// binding.
func TestX5CAttestationVerifier_Revocation(t *testing.T) {
	a, b := newTestProvider(t, "provider A"), newTestProvider(t, "provider B")
	leaf, key := a.leafNaming(t, providerA)
	ka := keyAttestationWithIssuer(t, key, leaf, providerA)
	for binding, v := range twoProviderVerifiers(a, b) {
		t.Run(fmt.Sprintf("binding %d", binding), func(t *testing.T) {
			testcert.RunRevocationCases(t, a.ca, a.caKey, leaf, func(t *testing.T, revocation certrevocation.Checker) error {
				v.Revocation = revocation
				_, _, err := v.ResolveAttestationKey(context.Background(), ka)
				return err
			})
		})
	}
}

// X5CProofBindingKeyResolver.Revocation refuses a proof whose x5c leaf
// is revoked.
func TestX5CProofBindingKeyResolver_Revocation(t *testing.T) {
	p := newTestProvider(t, "proof")
	leaf, _ := p.leafNaming(t, "")
	roots := x509.NewCertPool()
	roots.AddCert(p.ca)
	testcert.RunRevocationCases(t, p.ca, p.caKey, leaf, func(t *testing.T, revocation certrevocation.Checker) error {
		_, _, err := issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: revocation}.ResolveProofBindingKey(context.Background(), x5cProofHeader(leaf))
		return err
	})
}

// New refuses a Revocation that can't check anything, on either
// resolver.
func TestNew_RefusesIncompleteRevocation(t *testing.T) {
	roots := x509.NewCertPool()
	for name, mutate := range map[string]func(*issuer.Dependencies){
		"attestation_verifier": func(deps *issuer.Dependencies) {
			deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: roots, Revocation: certrevocation.CRLs{}}
		},
		"proof_binding_keys": func(deps *issuer.Dependencies) {
			deps.ProofBindingKeys = &issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: certrevocation.CRLs{}}
		},
	} {
		_, err := tryCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) { mutate(deps) })
		if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "Lists is required") {
			t.Errorf("%s: New: err = %v, want CRLs.Validate's refusal", name, err)
		}
	}
}
