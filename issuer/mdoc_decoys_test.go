package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// requestMdocDigests issues claims as an mdoc through f, checks it
// verifies, and returns how many digests its MSO lists for the
// org.iso.18013.5.1 namespace.
func requestMdocDigests(t *testing.T, f credentialEndpointFixture, claims *mdoc.Claims) int {
	t.Helper()
	nonce, err := f.iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce.CNonce)
	resp, err := f.iss.RequestCredential(context.Background(), grantingConfiguration(testMdocConfigID), issuer.CredentialRequest{
		CredentialConfigurationID: testMdocConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		MdocClaims:                claims,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	wire, err := base64.RawURLEncoding.DecodeString(resp.Credentials[0].Credential)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mdoc.Verify(signed, claims.DocType, &f.mdocSigner.Signer.(*ecdsa.PrivateKey).PublicKey, cose.ES256, mdoc.VerifyOptions{
		Now: func() time.Time { return claims.ValidFrom.Add(30 * time.Minute) },
	}); err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	mso, err := mdoc.IssuerAuthMSO(signed)
	if err != nil {
		t.Fatal(err)
	}
	return len(mso.ValueDigests["org.iso.18013.5.1"])
}

// With MdocSigner.Decoys, each issued mdoc's namespace carries from Min
// to Max decoy digests beyond its data elements, varying between
// credentials, added to the claims' own Claims.Decoys; it still
// verifies. Without, it carries only the claims' own.
func TestRequestCredential_Mdoc_Decoys(t *testing.T) {
	withOwn := func() *mdoc.Claims {
		c := testMdocClaims(t)
		c.Decoys = map[string]int{"org.iso.18013.5.1": 2}
		return c
	}
	if got := requestMdocDigests(t, newCredentialEndpointFixture(t), testMdocClaims(t)); got != 1 {
		t.Errorf("without decoys: %d digests, want 1", got)
	}
	if got := requestMdocDigests(t, newCredentialEndpointFixture(t), withOwn()); got != 3 {
		t.Errorf("with Claims.Decoys alone: %d digests, want 1 + 2", got)
	}

	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.MdocSigner.Decoys = &issuer.DecoyRange{Min: 1, Max: 4}
	})
	seen := map[int]bool{}
	for range 30 {
		decoys := requestMdocDigests(t, f, withOwn()) - 1 - 2
		if decoys < 1 || decoys > 4 {
			t.Fatalf("%d decoys from MdocSigner.Decoys, want 1 to 4", decoys)
		}
		seen[decoys] = true
	}
	if len(seen) < 2 {
		t.Errorf("30 credentials all carried %v decoys, want the count to vary", seen)
	}
}

// New refuses an MdocSigner.Decoys mdoc.Issue couldn't honor.
func TestNew_RejectsInvalidMdocDecoyRange(t *testing.T) {
	for _, d := range []issuer.DecoyRange{{Min: -1, Max: 2}, {Min: 0, Max: 0}, {Min: 3, Max: 2}, {Min: 0, Max: mdoc.MaxDecoys + 1}} {
		_, err := tryCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
			deps.MdocSigner.Decoys = &d
		})
		if err == nil || !strings.Contains(err.Error(), "mdoc_signer.decoys") {
			t.Errorf("New with mdoc decoys %+v = %v, want it refused", d, err)
		}
	}
}
