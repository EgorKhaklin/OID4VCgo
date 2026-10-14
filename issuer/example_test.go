package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
	"github.com/idfoundry/oid4vcgo/storage"
)

func exampleURL(parse func(string, ...fapi.URLOption) (fapi.URL, error), raw string) fapi.URL {
	u, err := parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// A Credential Issuer of one SD-JWT VC, with the endpoints it publishes
// and the stores it keeps, making a Credential Offer for the
// authorization code flow. In production, set Assurance to
// AssuranceProduction, which also requires durable stores, a signer
// certificate issued by a CA, and a status check on key attestations.
func ExampleNew() {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	iss, err := issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    exampleURL(fapi.ParseIssuerURL, "https://issuer.example.com"),
		Endpoints: issuer.Endpoints{
			Credential: exampleURL(fapi.ParseEndpointURL, "https://issuer.example.com/credential"),
			Nonce:      exampleURL(fapi.ParseEndpointURL, "https://issuer.example.com/nonce"),
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute, CredentialOfferLifetime: time.Hour},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"pid": {
				Format: sdjwtvc.CredentialFormat, Scope: "pid", VCT: "urn:eudi:pid:1",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				CredentialSigningAlgValuesSupported:  []string{"ES256"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Clock: issuer.ClockFunc(time.Now), Random: rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{Signer: signer, Alg: oid4vci.ES256},
		Nonces:      storage.NewNonceStore(), CredentialOffers: storage.NewCredentialOfferStore(),
		DeferredTransactions: storage.NewDeferredTransactionStore(), Notifications: storage.NewNotificationStore(),
	})
	if err != nil {
		panic(err)
	}

	// Serve iss.Metadata() at /.well-known/openid-credential-issuer, and
	// the Credential Endpoint as ExampleIssuer_CredentialHandler shows.
	// issuer_state ties the authorization the Wallet gets back to this
	// offer's holder.
	offer, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"pid"},
		Grants:                     &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: "holder-session-1"}},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(strings.SplitN(offer.URI, "?", 2)[0], iss.Metadata().CredentialIssuer)
	// Output: openid-credential-offer:// https://issuer.example.com
}

// The Credential Endpoint: tokens checks each request's access token
// and its DPoP proof, here with a fapigo resource verifier sharing the
// Authorization Server's keys (fapiresource.New). Prepare decides what
// to issue for the token's subject. The handler's URL is the
// Credential Endpoint Config.Endpoints publishes.
func ExampleIssuer_CredentialHandler() {
	var iss *issuer.Issuer            // from issuer.New, as in ExampleNew
	var tokens *fapiresource.Verifier // from fapiresource.New
	lookup := func(subject string) (string, bool) { return "Jean", subject != "" }

	handler, err := iss.CredentialHandler(issuer.CredentialHandlerConfig{
		Tokens: tokens,
		Prepare: func(_ context.Context, grant issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			givenName, ok := lookup(grant.Subject)
			if !ok {
				return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "no credential for this holder")
			}
			req.SDJWTClaims = &sdjwtvc.Claims{
				VCT:        "urn:eudi:pid:1",
				Additional: map[string]any{"given_name": sdjwtvc.SD(givenName)},
			}
			return nil, nil
		},
	})
	if err != nil {
		panic(err)
	}
	http.Handle("POST /credential", handler)
}
