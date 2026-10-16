package issuer_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// dpopProof is a DPoP proof for the token endpoint, as the wallet makes
// one, with method, URL and clock as given.
func (f preAuthorizedCodeFixture) dpopProof(t *testing.T, method, url string, clock time.Time) string {
	t.Helper()
	proof, err := testWalletForDPoP(t, clock).GenerateDPoPProof(testP256Key(t), method, url, "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	return proof
}

// The pre-authorized code grant's negative vectors not already in
// TestExchangePreAuthorizedCode_Rejects: a code redeemed twice, and
// DPoP proofs that are well formed but wrong for this request (RFC
// 9449 §4.3), each refused with its error code. The unchanged request
// is the control.
func TestPreAuthorizedCodeNegativeVectors(t *testing.T) {
	ctx := context.Background()
	exchange := func(f preAuthorizedCodeFixture, proof string) error {
		_, err := f.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: "code-1", DPoPProof: proof, TokenEndpoint: testTokenEndpointURL(t),
		})
		return err
	}
	fresh := func() preAuthorizedCodeFixture {
		f := newPreAuthorizedCodeFixture(t)
		f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
		return f
	}
	if f := fresh(); exchange(f, f.validProof(t)) != nil {
		t.Fatal("the control is refused, so no refusal below means anything")
	}
	endpoint := testTokenEndpointURL(t).String()
	for _, vec := range []struct {
		id, clause string
		code       issuer.ErrorCode
		proof      func(f preAuthorizedCodeFixture) string
	}{
		{"code-redeemed-twice", "RFC 6749 §4.1.2 / OpenID4VCI 1.0 §6.1 (a code is used once)", issuer.ErrorInvalidGrant,
			func(f preAuthorizedCodeFixture) string {
				if err := exchange(f, f.validProof(t)); err != nil {
					t.Fatalf("the first exchange: %v", err)
				}
				return f.validProof(t)
			}},
		{"dpop-htm-not-post", "RFC 9449 §4.3 (htm)", issuer.ErrorInvalidDPoPProof,
			func(f preAuthorizedCodeFixture) string { return f.dpopProof(t, "GET", endpoint, f.now) }},
		{"dpop-htu-another-endpoint", "RFC 9449 §4.3 (htu)", issuer.ErrorInvalidDPoPProof,
			func(f preAuthorizedCodeFixture) string {
				return f.dpopProof(t, "POST", "https://issuer.example.com/another", f.now)
			}},
		{"dpop-iat-too-old", "RFC 9449 §4.3 (iat within an acceptable window)", issuer.ErrorInvalidDPoPProof,
			func(f preAuthorizedCodeFixture) string {
				return f.dpopProof(t, "POST", endpoint, f.now.Add(-time.Hour))
			}},
		{"dpop-iat-in-the-future", "RFC 9449 §4.3 (iat within an acceptable window)", issuer.ErrorInvalidDPoPProof,
			func(f preAuthorizedCodeFixture) string { return f.dpopProof(t, "POST", endpoint, f.now.Add(time.Hour)) }},
		{"dpop-proof-replayed", "RFC 9449 §11.1 (jti replay)", issuer.ErrorInvalidDPoPProof,
			func(f preAuthorizedCodeFixture) string {
				proof := f.validProof(t)
				f.issue(t, "code-0", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
				if _, err := f.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
					PreAuthorizedCode: "code-0", DPoPProof: proof, TokenEndpoint: testTokenEndpointURL(t),
				}); err != nil {
					t.Fatalf("the proof's first use: %v", err)
				}
				return proof
			}},
	} {
		t.Run(vec.id, func(t *testing.T) {
			f := fresh()
			err := exchange(f, vec.proof(f))
			if err == nil {
				t.Fatalf("accepted (%s)", vec.clause)
			}
			requireIssuerErrorCode(t, err, vec.code)
		})
	}
}
