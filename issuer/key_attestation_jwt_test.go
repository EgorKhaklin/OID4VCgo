package issuer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// keyAttestationForJWT is a key attestation for the jwt proof type's
// key_attestation header: it has the exp Appendix D.1 requires there,
// unless noExp.
func keyAttestationForJWT(t *testing.T, signer *ecdsa.PrivateKey, nonce string, noExp bool, keys ...crypto.PublicKey) string {
	t.Helper()
	raws := make([]json.RawMessage, len(keys))
	for i, pub := range keys {
		raws[i] = jwkJSON(t, pub)
	}
	claims := attestation.Claims{IssuedAt: time.Now().Unix(), AttestedKeys: raws, Nonce: nonce}
	if !noExp {
		exp := time.Now().Add(time.Hour).Unix()
		claims.ExpiresAt = &exp
	}
	compact, err := attestation.Issue(signer, jose.ES256, attestation.Header{}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// jwtProofWithKeyAttestation is a jwt proof by key carrying
// keyAttestation in its header (Appendix F.1).
func jwtProofWithKeyAttestation(t *testing.T, key *ecdsa.PrivateKey, nonce, keyAttestation string) string {
	t.Helper()
	return jwtProofWithKeyAttestationFor(t, key, testIssuer, nonce, keyAttestation)
}

// jwtProofWithKeyAttestationFor is jwtProofWithKeyAttestation with aud.
func jwtProofWithKeyAttestationFor(t *testing.T, key *ecdsa.PrivateKey, aud, nonce, keyAttestation string) string {
	t.Helper()
	var jwkObj map[string]any
	if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"aud": aud, "iat": time.Now().Unix(), "nonce": nonce})
	raw, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj, "key_attestation": keyAttestation}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A jwt proof carrying a key_attestation (Appendix D.1, F.1, HAIP 1.0
// §4.5.1) is issued a Credential for each key the attestation attests,
// once the attestation verifies, has an exp, carries the proof's
// c_nonce, and attests the key the proof is signed with.
func TestRequestCredential_JWTProofKeyAttestation(t *testing.T) {
	required := func(cfg *issuer.Config, _ *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		jwt := c.ProofTypesSupported[oid4vci.ProofTypeJWT]
		jwt.KeyAttestationsRequired = &oid4vci.KeyAttestationRequirement{}
		c.ProofTypesSupported[oid4vci.ProofTypeJWT] = jwt
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
	}
	a, b := testP256Key(t), testP256Key(t)
	type proofs func(f credentialEndpointFixture, nonce string) []string
	for name, tc := range map[string]struct {
		proofs      proofs
		credentials int
		code        issuer.ErrorCode
	}{
		"one proof, two attested keys": {proofs: func(f credentialEndpointFixture, n string) []string {
			return []string{jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey, &b.PublicKey))}
		}, credentials: 2},
		"a proof per key, one attestation repeated": {proofs: func(f credentialEndpointFixture, n string) []string {
			ka := keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey, &b.PublicKey)
			return []string{jwtProofWithKeyAttestation(t, a, n, ka), jwtProofWithKeyAttestation(t, b, n, ka)}
		}, credentials: 2},
		"a proof by a key the attestation doesn't attest": {proofs: func(f credentialEndpointFixture, n string) []string {
			return []string{jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &b.PublicKey))}
		}, code: issuer.ErrorInvalidProof},
		"an attestation without exp": {proofs: func(f credentialEndpointFixture, n string) []string {
			return []string{jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, f.attestationSigner, n, true, &a.PublicKey))}
		}, code: issuer.ErrorInvalidProof},
		"an attestation with another nonce": {proofs: func(f credentialEndpointFixture, n string) []string {
			return []string{jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, f.attestationSigner, "another", false, &a.PublicKey))}
		}, code: issuer.ErrorInvalidNonce},
		"an attestation by an untrusted signer": {proofs: func(_ credentialEndpointFixture, n string) []string {
			return []string{jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, testP256Key(t), n, false, &a.PublicKey))}
		}, code: issuer.ErrorInvalidProof},
		"no key_attestation where one is required": {proofs: func(_ credentialEndpointFixture, n string) []string {
			return []string{buildJWTProof(t, a, testIssuer, n)}
		}, code: issuer.ErrorInvalidProof},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, required)
			resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: tc.proofs(f, f.issueNonce(t))},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if tc.code != "" {
				assertIssuerError(t, err, tc.code)
				return
			}
			if err != nil || len(resp.Credentials) != tc.credentials {
				t.Fatalf("issued %d credentials, %v; want %d", len(resp.Credentials), err, tc.credentials)
			}
		})
	}
}

// An issuer offering the jwt proof type without key_attestations_required
// beside the attestation proof type, as a HAIP wallet finds it, takes a
// jwt proof carrying a key_attestation: it's verified as one required
// would be, and a Credential is issued for each key it attests. A proof
// whose aud is another issuer's is refused with it, which is what binds
// the key attestation to this issuer.
func TestRequestCredential_JWTProofKeyAttestationNotRequired(t *testing.T) {
	a, b := testP256Key(t), testP256Key(t)
	request := func(f credentialEndpointFixture, proofs []string) (oid4vci.CredentialResponse, error) {
		return f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
			SDJWTClaims:               testSDJWTClaims(),
		})
	}
	f := newCredentialEndpointFixture(t)
	conf := f.iss.Metadata().CredentialConfigurationsSupported[testSDJWTConfigID]
	if conf.ProofTypesSupported[oid4vci.ProofTypeJWT].KeyAttestationsRequired != nil {
		t.Fatal("the fixture's jwt proof type requires key attestations")
	}
	if _, ok := conf.ProofTypesSupported[oid4vci.ProofTypeAttestation]; !ok {
		t.Fatal("the fixture offers no attestation proof type")
	}
	n := f.issueNonce(t)
	resp, err := request(f, []string{jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey, &b.PublicKey))})
	if err != nil || len(resp.Credentials) != 2 {
		t.Fatalf("issued %d credentials, %v; want 2", len(resp.Credentials), err)
	}

	f = newCredentialEndpointFixture(t)
	n = f.issueNonce(t)
	_, err = request(f, []string{jwtProofWithKeyAttestationFor(t, a, "https://other-issuer.example.com", n, keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey))})
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

// batch_size bounds the keys a request resolves, not only its proofs:
// jwt proofs with and without a key_attestation in one request are
// refused once together they resolve more keys than batch_size,
// whichever comes first.
func TestRequestCredential_JWTProofsMixedKeyAttestationBatchSize(t *testing.T) {
	a, b, c := testP256Key(t), testP256Key(t), testP256Key(t)
	for name, proofs := range map[string]func(f credentialEndpointFixture, n string) []string{
		"key attestation first": func(f credentialEndpointFixture, n string) []string {
			ka := keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey, &b.PublicKey)
			return []string{jwtProofWithKeyAttestation(t, a, n, ka), buildJWTProof(t, c, testIssuer, n)}
		},
		"plain proof first": func(f credentialEndpointFixture, n string) []string {
			ka := keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey, &b.PublicKey)
			return []string{buildJWTProof(t, c, testIssuer, n), jwtProofWithKeyAttestation(t, a, n, ka)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t) // batch_size 2
			_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs(f, f.issueNonce(t))},
				SDJWTClaims:               testSDJWTClaims(),
			})
			assertIssuerError(t, err, issuer.ErrorInvalidProof)
		})
	}
}
