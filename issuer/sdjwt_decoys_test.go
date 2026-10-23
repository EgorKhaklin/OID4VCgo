package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// sdDigestsAndDisclosures counts an issued SD-JWT VC's top-level _sd
// digests and the Disclosures it carries.
func sdDigestsAndDisclosures(t *testing.T, credential string) (digests, disclosures int) {
	t.Helper()
	parts := strings.Split(credential, "~")
	segments := strings.Split(parts[0], ".")
	if len(segments) != 3 {
		t.Fatalf("issuer-signed JWT has %d segments", len(segments))
	}
	raw, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload struct {
		SD []string `json:"_sd"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	for _, d := range parts[1:] {
		if d != "" {
			disclosures++
		}
	}
	return len(payload.SD), disclosures
}

// With SDJWTSigner.Decoys, each issued SD-JWT VC's _sd array carries
// from Min to Max decoy digests beyond its real ones, and still
// verifies; without, it carries none.
func TestRequestCredential_SDJWT_Decoys(t *testing.T) {
	claims := func() *sdjwtvc.Claims {
		return &sdjwtvc.Claims{
			VCT:        "https://credentials.example.com/identity_credential",
			Additional: map[string]any{"given_name": sdjwtvc.SD("Erika"), "family_name": sdjwtvc.SD("Mustermann")},
		}
	}
	issue := func(t *testing.T, f credentialEndpointFixture) string {
		t.Helper()
		nonce, err := f.iss.RequestNonce(context.Background())
		if err != nil {
			t.Fatalf("RequestNonce: %v", err)
		}
		proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce.CNonce)
		resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
			SDJWTClaims:               claims(),
		})
		if err != nil {
			t.Fatalf("RequestCredential: %v", err)
		}
		credential := resp.Credentials[0].Credential
		if _, _, err := sdjwtvc.Verify(credential, &f.sdjwtSigner.Signer.(*ecdsa.PrivateKey).PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
			RequireKeyBinding: sdjwtvc.KeyBindingNotRequired,
		}); err != nil {
			t.Fatalf("sdjwtvc.Verify: %v", err)
		}
		return credential
	}

	if digests, disclosures := sdDigestsAndDisclosures(t, issue(t, newCredentialEndpointFixture(t))); digests != disclosures {
		t.Errorf("without decoys: %d digests for %d disclosures", digests, disclosures)
	}

	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.SDJWTSigner.Decoys = &issuer.DecoyRange{Min: 1, Max: 4}
	})
	seen := map[int]bool{}
	for range 40 {
		digests, disclosures := sdDigestsAndDisclosures(t, issue(t, f))
		decoys := digests - disclosures
		if decoys < 1 || decoys > 4 {
			t.Fatalf("%d decoys, want 1 to 4", decoys)
		}
		seen[decoys] = true
	}
	if len(seen) < 2 {
		t.Errorf("40 credentials all carried %v decoys, want the count to vary", seen)
	}
}

// New refuses a DecoyRange sdjwtvc.Issue couldn't honor.
func TestNew_RejectsInvalidDecoyRange(t *testing.T) {
	for _, d := range []issuer.DecoyRange{{Min: -1, Max: 2}, {Min: 0, Max: 0}, {Min: 3, Max: 2}, {Min: 0, Max: sdjwtvc.MaxDecoys + 1}} {
		_, err := tryCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
			deps.SDJWTSigner.Decoys = &d
		})
		if err == nil || !strings.Contains(err.Error(), "decoys") {
			t.Errorf("New with decoys %+v = %v, want it refused", d, err)
		}
	}
}
