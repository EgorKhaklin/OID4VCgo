package issuer_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// TestIssuedSDJWTNamesTheIssuer: an SD-JWT VC whose Prepare set no iss
// names Config.Issuer, so a Wallet refuses it from another issuer that
// relayed the Wallet's key attestation here and hands the credential
// on as its own; one Prepare gave an iss keeps it.
func TestIssuedSDJWTNamesTheIssuer(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	leaf, leafKey := testcert.Leaf(t, "issuer", ca, caKey)
	holder := testP256Key(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(claims sdjwtvc.Claims) (string, map[string]any) {
		t.Helper()
		f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
			deps.SDJWTSigner.Signer = leafKey
			deps.SDJWTSigner.IssuerCertificate = leaf
		})
		att := buildAttestation(t, f.attestationSigner, f.issueNonce(t), &holder.PublicKey)
		resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{
			ClientIdentity: issuer.KnownClientID("wallet"), Scopes: []string{"identity_credential"},
		}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
			SDJWTClaims:               &claims,
		})
		if err != nil {
			t.Fatalf("RequestCredential: %v", err)
		}
		cred := resp.Credentials[0].Credential
		raw, err := base64.RawURLEncoding.DecodeString(strings.Split(strings.Split(cred, "~")[0], ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		return cred, payload
	}

	cred, payload := issue(*testSDJWTClaims())
	if payload["iss"] != testIssuer {
		t.Fatalf("iss = %v, want %q", payload["iss"], testIssuer)
	}
	params := wallet.VerifyIssuedCredentialParams{
		Configuration: oid4vci.CredentialConfigurationMetadata{Format: sdjwtvc.CredentialFormat, VCT: testSDJWTClaims().VCT, CryptographicBindingMethodsSupported: []string{"jwk"}},
		Credential:    cred, HolderKey: &holder.PublicKey, IssuerRoots: roots,
		CredentialIssuer: "https://another-issuer.example",
	}
	if _, err := wallet.VerifyIssuedCredential(context.Background(), params); err == nil {
		t.Fatal("a Wallet that asked another issuer accepted the credential")
	}
	params.CredentialIssuer = testIssuer
	if _, err := wallet.VerifyIssuedCredential(context.Background(), params); err != nil {
		t.Fatalf("a Wallet that asked this issuer refused the credential: %v", err)
	}

	claims := *testSDJWTClaims()
	claims.Iss = "https://issuer.example.com/pid"
	if _, payload := issue(claims); payload["iss"] != claims.Iss {
		t.Fatalf("iss = %v, want Prepare's %q", payload["iss"], claims.Iss)
	}
}
