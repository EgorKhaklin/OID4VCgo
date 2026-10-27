package issuer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// attesterCRLs is a Wallet Provider CA whose key attestation signing
// certificate an X5CAttestationVerifier checks against the CRLs in
// lists, which a test changes between requests.
type attesterCRLs struct {
	provider testProvider
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
	lists    []*x509.RevocationList
	// fail, when set, is what the Revocation checker returns instead
	// of checking lists.
	fail error
}

func newAttesterCRLs(t *testing.T) *attesterCRLs {
	t.Helper()
	a := &attesterCRLs{provider: newTestProvider(t, "wallet provider")}
	a.leaf, a.leafKey = a.provider.leafNaming(t, "")
	a.lists = []*x509.RevocationList{testcert.CRL(t, a.provider.ca, a.provider.caKey)}
	return a
}

func (a *attesterCRLs) CheckRevocation(ctx context.Context, check certrevocation.Check) error {
	if a.fail != nil {
		return a.fail
	}
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return a.lists, nil }}.CheckRevocation(ctx, check)
}

// use makes deps verify key attestations under a's CA, checking a's
// CRLs.
func (a *attesterCRLs) use(deps *issuer.Dependencies) {
	roots := x509.NewCertPool()
	roots.AddCert(a.provider.ca)
	deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: roots, Revocation: a}
}

// keyAttestation is a key attestation signed under a's signing
// certificate, with an exp, attesting keys.
func (a *attesterCRLs) keyAttestation(t *testing.T, nonce string, keys ...crypto.PublicKey) string {
	t.Helper()
	header := attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(a.leaf.Raw)}}
	return keyAttestationWith(t, a.leafKey, header, nonce, false, nil, keys...)
}

// undecided are the attester revocation outcomes that decide nothing:
// the CRL has gone stale, a Checker whose source is down, and a request
// whose context ended.
func (a *attesterCRLs) undecided(t *testing.T) map[string]func() {
	t.Helper()
	return map[string]func(){
		"no current CRL":      func() { a.lists = nil },
		"checker unreachable": func() { a.fail = errors.New("OCSP responder unreachable") },
		"deadline exceeded":   func() { a.fail = fmt.Errorf("fetch: %w", context.DeadlineExceeded) },
	}
}

// restore makes a's checks pass again.
func (a *attesterCRLs) restore(t *testing.T) {
	t.Helper()
	a.lists, a.fail = []*x509.RevocationList{testcert.CRL(t, a.provider.ca, a.provider.caKey)}, nil
}

// revoke revokes a's signing certificate.
func (a *attesterCRLs) revoke(t *testing.T) {
	t.Helper()
	a.lists, a.fail = []*x509.RevocationList{testcert.CRL(t, a.provider.ca, a.provider.caKey, a.leaf.SerialNumber)}, nil
}

// TestRequestCredential_AttesterRevocationUndecided: a key attestation
// whose signing certificate's revocation can't be decided now is a
// server error at the Credential Endpoint, for an attestation-type
// proof and a jwt proof's key_attestation header alike, not
// invalid_proof; a revoked one is invalid_proof.
func TestRequestCredential_AttesterRevocationUndecided(t *testing.T) {
	key := testP256Key(t)
	proofs := map[string]func(a *attesterCRLs, n string) map[string][]string{
		"attestation proof": func(a *attesterCRLs, n string) map[string][]string {
			return map[string][]string{oid4vci.ProofTypeAttestation: {a.keyAttestation(t, n, &key.PublicKey)}}
		},
		"key_attestation header": func(a *attesterCRLs, n string) map[string][]string {
			return map[string][]string{oid4vci.ProofTypeJWT: {jwtProofWithKeyAttestation(t, key, n, a.keyAttestation(t, n, &key.PublicKey))}}
		},
	}
	for proofName, proof := range proofs {
		a := newAttesterCRLs(t)
		outcomes := map[string]func(){"valid": func() { a.restore(t) }, "revoked": func() { a.revoke(t) }}
		for name, set := range a.undecided(t) {
			outcomes["unknown: "+name] = set
		}
		for name, set := range outcomes {
			t.Run(proofName+", "+name, func(t *testing.T) {
				f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) { a.use(deps) })
				a.restore(t)
				set()
				_, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
					CredentialConfigurationID: testSDJWTConfigID,
					Proofs:                    proof(a, f.issueNonce(t)),
					SDJWTClaims:               testSDJWTClaims(),
				})
				outcome, _, _ := strings.Cut(name, ":")
				assertAttestationStatusOutcome(t, outcome, err)
			})
		}
	}
}

// TestRequestCredential_JWTKeyAttestationHeaderStatus: a jwt proof's
// key_attestation header has its status checked, as an attestation-type
// proof's is: revoked is invalid_proof, undetermined a server error.
func TestRequestCredential_JWTKeyAttestationHeaderStatus(t *testing.T) {
	for name, statusErr := range map[string]error{
		"valid":   nil,
		"revoked": fmt.Errorf("status SUSPENDED: %w", issuer.ErrKeyAttestationRevoked),
		"unknown": errors.New("status list unreachable"),
	} {
		t.Run(name, func(t *testing.T) {
			checked := 0
			f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
				deps.AttestationStatus = attestationStatusFunc(func(context.Context, issuer.VerifiedKeyAttestation) error {
					checked++
					return statusErr
				})
			})
			key := testP256Key(t)
			n := f.issueNonce(t)
			_, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {jwtProofWithKeyAttestation(t, key, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &key.PublicKey))}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if checked != 1 {
				t.Errorf("status checked %d times, want once", checked)
			}
			assertAttestationStatusOutcome(t, name, err)
		})
	}
}

// TestRequestCredential_JWTKeyAttestationHeaderRequirement: a jwt
// proof's key_attestation must meet key_attestations_required, as an
// attestation-type proof's must, before its status is checked.
func TestRequestCredential_JWTKeyAttestationHeaderRequirement(t *testing.T) {
	checked := 0
	requireHigh := func(cfg *issuer.Config, deps *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		jwt := c.ProofTypesSupported[oid4vci.ProofTypeJWT]
		jwt.KeyAttestationsRequired = &oid4vci.KeyAttestationRequirement{KeyStorage: []string{string(attestation.ISO18045High)}}
		c.ProofTypesSupported[oid4vci.ProofTypeJWT] = jwt
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		deps.AttestationStatus = attestationStatusFunc(func(context.Context, issuer.VerifiedKeyAttestation) error { checked++; return nil })
	}
	key := testP256Key(t)
	for name, tc := range map[string]struct {
		levels []attestation.AttackPotentialResistance
		ok     bool
	}{
		"meets it":         {[]attestation.AttackPotentialResistance{attestation.ISO18045Moderate, attestation.ISO18045High}, true},
		"falls short":      {[]attestation.AttackPotentialResistance{attestation.ISO18045Moderate}, false},
		"asserts no level": {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			checked = 0
			f := newCredentialEndpointFixture(t, requireHigh)
			n := f.issueNonce(t)
			ka := keyAttestationWith(t, f.attestationSigner, attestation.Header{}, n, false, tc.levels, &key.PublicKey)
			_, err := f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {jwtProofWithKeyAttestation(t, key, n, ka)}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if tc.ok {
				if err != nil {
					t.Fatalf("RequestCredential: %v", err)
				}
				return
			}
			assertIssuerError(t, err, issuer.ErrorInvalidProof)
			if checked != 0 {
				t.Errorf("status checked %d times for an attestation that fails key_attestations_required, want none", checked)
			}
		})
	}
}

// TestDeferral_AttesterRevocationUndecided: a deferred transaction's
// re-check that can't decide the key attestation signer's revocation —
// its CRL gone stale, its revocation source down, the context ended —
// leaves the transaction pending, which then issues once revocation can
// be checked; a signer revoked since denies it.
func TestDeferral_AttesterRevocationUndecided(t *testing.T) {
	a := newAttesterCRLs(t)
	outcomes := a.undecided(t)
	outcomes["revoked"] = func() { a.revoke(t) }
	for name, set := range outcomes {
		t.Run(name, func(t *testing.T) {
			f := newDeferralFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) { a.use(deps) })
			a.restore(t)
			ctx := context.Background()
			key := testP256Key(t)
			n := f.issueNonce(t)
			resp, err := f.iss.RequestCredential(ctx, deferralAuth, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {jwtProofWithKeyAttestation(t, key, n, a.keyAttestation(t, n, &key.PublicKey))}},
				Defer:                     &issuer.Deferral{},
			})
			if err != nil {
				t.Fatalf("RequestCredential (deferred): %v", err)
			}

			set()
			err = f.iss.IssueDeferredCredential(ctx, resp.TransactionID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
			if name == "revoked" {
				if !errors.Is(err, issuer.ErrDeferredKeyAttestation) || !errors.Is(err, certrevocation.ErrRevoked) {
					t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredKeyAttestation for the revoked signer", err)
				}
				_, pollErr := f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: resp.TransactionID})
				assertIssuerError(t, pollErr, issuer.ErrorCredentialRequestDenied)
				return
			}
			if !errors.Is(err, issuer.ErrDeferredAttestationStatusUnknown) || errors.Is(err, issuer.ErrDeferredKeyAttestation) {
				t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredAttestationStatusUnknown, the transaction kept", err)
			}
			a.restore(t)
			if err := f.iss.IssueDeferredCredential(ctx, resp.TransactionID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
				t.Fatalf("IssueDeferredCredential once revocation can be checked: %v", err)
			}
		})
	}
}

// TestDeferral_RechecksEveryKeyAttestation: one key attestation whose
// status can't be checked doesn't keep a transaction pending when
// another is revoked, whichever comes first; with both undetermined it
// stays pending.
func TestDeferral_RechecksEveryKeyAttestation(t *testing.T) {
	unknown := errors.New("status list unreachable")
	revoked := fmt.Errorf("status INVALID: %w", issuer.ErrKeyAttestationRevoked)
	for name, tc := range map[string]struct {
		statuses []error
		denied   bool
	}{
		"unknown, then revoked": {[]error{unknown, revoked}, true},
		"revoked, then unknown": {[]error{revoked, unknown}, true},
		"both unknown":          {[]error{unknown, unknown}, false},
	} {
		t.Run(name, func(t *testing.T) {
			var statuses []error
			f := newDeferralFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
				deps.AttestationStatus = attestationStatusFunc(func(context.Context, issuer.VerifiedKeyAttestation) error {
					if len(statuses) == 0 {
						return nil
					}
					s := statuses[0]
					statuses = statuses[1:]
					return s
				})
			})
			ctx := context.Background()
			a, b := testP256Key(t), testP256Key(t)
			n := f.issueNonce(t)
			resp, err := f.iss.RequestCredential(ctx, deferralAuth, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs: map[string][]string{oid4vci.ProofTypeJWT: {
					jwtProofWithKeyAttestation(t, a, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &a.PublicKey)),
					jwtProofWithKeyAttestation(t, b, n, keyAttestationForJWT(t, f.attestationSigner, n, false, &b.PublicKey)),
				}},
				Defer: &issuer.Deferral{},
			})
			if err != nil {
				t.Fatalf("RequestCredential (deferred): %v", err)
			}
			if record, err := f.store.Get(ctx, resp.TransactionID); err != nil || len(record.KeyAttestations) != 2 {
				t.Fatalf("record = %+v, %v; want two key attestations", record, err)
			}
			statuses = tc.statuses
			err = f.iss.IssueDeferredCredential(ctx, resp.TransactionID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
			if tc.denied {
				if !errors.Is(err, issuer.ErrDeferredKeyAttestation) || !errors.Is(err, issuer.ErrKeyAttestationRevoked) {
					t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredKeyAttestation", err)
				}
				return
			}
			if !errors.Is(err, issuer.ErrDeferredAttestationStatusUnknown) {
				t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredAttestationStatusUnknown", err)
			}
			if err := f.iss.IssueDeferredCredential(ctx, resp.TransactionID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
				t.Fatalf("IssueDeferredCredential once the status can be checked: %v", err)
			}
		})
	}
}

// TestRequestCredential_ProofBindingRevocationUndecided: a jwt proof
// whose x5c certificate's revocation can't be decided now is a server
// error, as a key attestation signer's is; a revoked one is
// invalid_proof.
func TestRequestCredential_ProofBindingRevocationUndecided(t *testing.T) {
	ca := newAttesterCRLs(t)
	outcomes := map[string]func(){"valid": func() { ca.restore(t) }, "revoked": func() { ca.revoke(t) }}
	for name, set := range ca.undecided(t) {
		outcomes["unknown: "+name] = set
	}
	for name, set := range outcomes {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
				roots := x509.NewCertPool()
				roots.AddCert(ca.provider.ca)
				deps.ProofBindingKeys = issuer.X5CProofBindingKeyResolver{Roots: roots, Revocation: ca}
			})
			ca.restore(t)
			set()
			payload := fmt.Sprintf(`{"aud":%q,"iat":%d,"nonce":%q}`, testIssuer, time.Now().Unix(), f.issueNonce(t))
			proof, err := jose.Sign(jose.ES256, ca.leafKey, map[string]any{
				"typ": "openid4vci-proof+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(ca.leaf.Raw)},
			}, []byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.iss.RequestCredential(context.Background(), deferralAuth, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			outcome, _, _ := strings.Cut(name, ":")
			assertAttestationStatusOutcome(t, outcome, err)
		})
	}
}
