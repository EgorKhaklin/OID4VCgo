package issuer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The credential signed is of the configuration the token authorized:
// claims of another vct or docType, from a Prepare or PerCredential
// that built the wrong ones, are refused rather than signed (OpenID4VCI
// §8). A vct whose aka_vcts lists the configuration's is of it.
func TestRequestCredential_RefusesAnotherType(t *testing.T) {
	sdjwt := func(claims *sdjwtvc.Claims) error {
		f := newCredentialEndpointFixture(t)
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
			SDJWTClaims:               claims,
		})
		return err
	}
	if err := sdjwt(&sdjwtvc.Claims{VCT: testVCT}); err != nil {
		t.Errorf("the configuration's vct: %v", err)
	}
	if err := sdjwt(&sdjwtvc.Claims{VCT: "https://example.com/full_pid"}); err == nil || !strings.Contains(err.Error(), "vct") {
		t.Errorf("another vct: %v, want it refused for its vct", err)
	}
	if err := sdjwt(&sdjwtvc.Claims{VCT: testVCT + ":derived", AkaVCTs: []string{testVCT}}); err != nil {
		t.Errorf("a derived vct listing the configuration's in aka_vcts: %v", err)
	}

	f := newCredentialEndpointFixture(t)
	claims := testMdocClaims(t)
	claims.DocType = "org.iso.23220.photoid.1"
	mdocAuth := issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{{
		Type: "openid_credential", CredentialConfigurationID: testMdocConfigID, CredentialIdentifiers: []string{"mdl-1"},
	}}}
	_, err := f.iss.RequestCredential(context.Background(), mdocAuth, issuer.CredentialRequest{
		CredentialIdentifier: "mdl-1",
		Proofs:               map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		MdocClaims:           claims,
	})
	if err == nil || !strings.Contains(err.Error(), "docType") {
		t.Errorf("an mdoc of another docType: %v, want it refused for its docType", err)
	}
}

// ResolveCredentialConfiguration names the configuration a request
// resolves to, by its id or by a credential_identifier.
func TestResolveCredentialConfiguration(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	id, err := f.iss.ResolveCredentialConfiguration(issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID})
	if err != nil || id != testSDJWTConfigID {
		t.Errorf("by id: %q, %v", id, err)
	}
	auth := issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{{
		Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{"cid-1"},
	}}}
	if id, err := f.iss.ResolveCredentialConfiguration(auth, issuer.CredentialRequest{CredentialIdentifier: "cid-1"}); err != nil || id != testSDJWTConfigID {
		t.Errorf("by credential_identifier: %q, %v", id, err)
	}
	if _, err := f.iss.ResolveCredentialConfiguration(issuer.AuthorizedRequest{Scopes: []string{"other"}}, issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID}); err == nil {
		t.Error("resolved a configuration the token doesn't authorize")
	}
}
