package verifier_test

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// otherECDSAEncoding is jws, an ES256 JWS, with its signature's other
// valid encoding: s replaced by n−s, which verifies too.
func otherECDSAEncoding(t *testing.T, jws string) string {
	t.Helper()
	i := strings.LastIndexByte(jws, '.')
	sig, err := base64.RawURLEncoding.DecodeString(jws[i+1:])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %v", err)
	}
	s := new(big.Int).SetBytes(sig[32:])
	s.Sub(elliptic.P256().Params().N, s)
	s.FillBytes(sig[32:])
	return jws[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
}

// Under multiple, one credential presented twice isn't two credentials:
// the response is refused, whether the copies are identical or differ
// only in what the holder controls — the KB-JWT, or the issuer
// signature's encoding.
func TestVerifyResponse_MultipleRefusesTheSameCredentialTwice(t *testing.T) {
	v := newTestVerifier(t)
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT), Multiple: true}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := testP256Key(t)
	fixture := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	other := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)

	// The same credential, with its issuer signature's other encoding
	// and a KB-JWT of its own.
	pres, err := sdjwtvc.Parse(fixture.compact)
	if err != nil {
		t.Fatal(err)
	}
	pres.IssuerJWT = otherECDSAEncoding(t, pres.IssuerJWT)
	pres.KeyBindingJWT, err = sdjwtvc.NewKeyBindingJWT(fixture.holderKey, jose.ES256, pres, sdjwtvc.SHA256, sdjwtvc.KeyBindingClaims{Audience: v.ClientID(), Nonce: built.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := pres.Compact()
	if err != nil {
		t.Fatal(err)
	}

	verify := func(presentations ...string) (verifier.VerifyResponseResult, error) {
		return v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: query, Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
			ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour,
			IssuerKeys: fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
		})
	}
	if result, err := verify(reencoded); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("the re-encoded presentation alone: %+v, %v; want it to verify", result, err)
	}
	for name, presentations := range map[string][]string{
		"identical":        {fixture.compact, other.compact, fixture.compact},
		"another encoding": {fixture.compact, reencoded},
	} {
		_, err := verify(presentations...)
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), "more than once") {
			t.Errorf("%s: VerifyResponse = %v, want it refused as the same credential twice", name, err)
		}
	}
	if result, err := verify(fixture.compact, other.compact); err != nil || len(result.Credentials) != 2 {
		t.Errorf("two credentials: %+v, %v; want both", result, err)
	}
}

// The same for an mdoc: two presentations of one mdoc, each with its
// own device signature, are one credential.
func TestVerifyResponse_MultipleRefusesTheSameMdocTwice(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	mf.query.Credentials[0].Multiple = true
	again := testmdoc.Present(t, mf.f, oid4vpmdoc.HandoverParams{
		ClientID: mf.v.ClientID(), Nonce: mf.nonce, ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
	})
	_, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
		r.Response.VPToken["mdl"] = append(r.Response.VPToken["mdl"], again)
	})
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("VerifyResponse = %v, want it refused as the same mdoc twice", err)
	}
}

// One credential may answer two credential queries (OpenID4VP 1.0
// §6.1), unless DistinctCredentials says each query wants its own — two
// adults, two documents — where it would be counted as both. Two
// credentials, one for each query, verify either way, and one presented
// twice for one query is refused either way.
func TestVerifyResponse_DistinctCredentialsRefusesOneForTwoQueries(t *testing.T) {
	v := newTestVerifier(t)
	meta := testverify.MustSDJWTVCMeta(t, testVCT)
	query := dcql.Query{Credentials: []dcql.CredentialQuery{
		{ID: "adult1", Format: sdjwtvc.CredentialFormat, Meta: meta},
		{ID: "adult2", Format: sdjwtvc.CredentialFormat, Meta: meta, Multiple: true},
	}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := testP256Key(t)
	fixture := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	other := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	verify := func(distinct bool, first string, second ...string) (verifier.VerifyResponseResult, error) {
		return v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query:         query,
			Response:      verifier.ParsedResponse{VPToken: map[string][]string{"adult1": {first}, "adult2": second}},
			ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour,
			IssuerKeys:          fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
			DistinctCredentials: distinct,
		})
	}

	_, err = verify(true, fixture.compact, fixture.compact)
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), `credential queries "adult1" and "adult2"`) {
		t.Errorf("DistinctCredentials: VerifyResponse = %v, want it refused as the same credential for two queries", err)
	}
	if result, err := verify(false, fixture.compact, fixture.compact); err != nil || len(result.Credentials) != 2 {
		t.Errorf("without DistinctCredentials: %+v, %v; want one credential answering both", result, err)
	}
	for _, distinct := range []bool{false, true} {
		if result, err := verify(distinct, fixture.compact, other.compact); err != nil || len(result.Credentials) != 2 {
			t.Errorf("DistinctCredentials %v, two credentials: %+v, %v; want both", distinct, result, err)
		}
		if _, err := verify(distinct, fixture.compact, other.compact, other.compact); err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Errorf("DistinctCredentials %v, one presented twice for one query: %v, want it refused", distinct, err)
		}
	}
}

// The same for an mdoc, each presentation with its own device
// signature.
func TestVerifyResponse_DistinctCredentialsRefusesOneMdocForTwoQueries(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	second := mf.query.Credentials[0]
	second.ID = "mdl2"
	mf.query.Credentials = append(mf.query.Credentials, second)
	again := testmdoc.Present(t, mf.f, oid4vpmdoc.HandoverParams{
		ClientID: mf.v.ClientID(), Nonce: mf.nonce, ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
	})
	verify := func(distinct bool) (verifier.VerifyResponseResult, error) {
		return mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
			r.Response.VPToken["mdl2"] = []string{again}
			r.DistinctCredentials = distinct
		})
	}
	_, err := verify(true)
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), `credential queries "mdl" and "mdl2"`) {
		t.Errorf("DistinctCredentials: VerifyResponse = %v, want it refused as the same mdoc for two queries", err)
	}
	if result, err := verify(false); err != nil || len(result.Credentials) != 2 {
		t.Errorf("without DistinctCredentials: %+v, %v; want one mdoc answering both", result, err)
	}
}
