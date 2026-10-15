package verifier_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A caller branches on why verification failed through Error.Reason,
// not the error's text.
func TestVerifyResponse_ErrorReason(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{vctCredentialQuery(t, "pid")}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := testP256Key(t)
	good := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	trusted := fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256}
	for name, tc := range map[string]struct {
		vpToken map[string][]string
		nonce   string
		keys    verifier.SDJWTVCIssuerKeyResolver
		want    verifier.Reason
	}{
		"unparseable":        {map[string][]string{"pid": {"not-an-sd-jwt"}}, built.Nonce, trusted, verifier.ReasonMalformed},
		"another issuer":     {map[string][]string{"pid": {good.compact}}, built.Nonce, fixedSDJWTVCIssuerKeyResolver{pub: &testP256Key(t).PublicKey, alg: jose.ES256}, verifier.ReasonInvalidCredential},
		"another nonce":      {map[string][]string{"pid": {good.compact}}, "another-nonce", trusted, verifier.ReasonHolderBinding},
		"query not answered": {map[string][]string{}, built.Nonce, trusted, verifier.ReasonNotAnswered},
	} {
		_, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: query, Response: verifier.ParsedResponse{VPToken: tc.vpToken}, ExpectedNonce: tc.nonce,
			IssuerKeys: tc.keys, MaxKeyBindingAge: time.Hour,
		})
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != tc.want {
			t.Errorf("%s: %v, want reason %q", name, err, tc.want)
		}
	}
}
