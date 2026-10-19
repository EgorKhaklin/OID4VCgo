package issuer_test

import (
	"context"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// A pre-authorized Token Request may carry authorization_details
// (§6.1.1); the Token Response then echoes them, with a
// credential_identifier each (§6.2). Their form is checked before the
// code is consumed. With authorization_servers in the metadata, each
// minted detail's locations is the Credential Issuer (§5.1.1).
func TestRedeemPreAuthorizedCode_AuthorizationDetails(t *testing.T) {
	verified := &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"}
	detail := func(id string) oid4vci.AuthorizationDetail {
		return oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: id}
	}
	newFixture := func(t *testing.T, authorizationServers bool) preAuthorizedCodeFixture {
		return newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
			cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
			cfg.Limits.MaxDPoPProofAge = 0
			deps.DPoPReplay = nil
			if authorizationServers {
				cfg.AuthorizationServers = []fapi.URL{mustEndpointURL(t, "https://as.example.com")}
			}
		})
	}
	redeem := func(f preAuthorizedCodeFixture, code string, details ...oid4vci.AuthorizationDetail) (issuer.RedeemedPreAuthorizedCode, error) {
		return f.iss.RedeemPreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: code, Verified: verified, AuthorizationDetails: details})
	}
	record := func(f preAuthorizedCodeFixture) issuer.PreAuthorizedCodeRecord {
		return issuer.PreAuthorizedCodeRecord{Subject: "holder-1", Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)}
	}

	t.Run("requested and granted by scope", func(t *testing.T) {
		f := newFixture(t, true)
		f.issue(t, "code-1", record(f))
		got, err := redeem(f, "code-1", detail("IdentityCredential"))
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		if len(got.AuthorizationDetails) != 1 || len(got.AuthorizationDetails[0].CredentialIdentifiers) != 1 ||
			len(got.AuthorizationDetails[0].Locations) != 1 || got.AuthorizationDetails[0].Locations[0] != testIssuer {
			t.Errorf("authorization_details = %+v, want one with an identifier and locations [%s]", got.AuthorizationDetails, testIssuer)
		}
	})
	t.Run("malformed, refused before the code is spent", func(t *testing.T) {
		f := newFixture(t, false)
		f.issue(t, "code-2", record(f))
		other := detail("IdentityCredential")
		other.Type = "payment_initiation"
		elsewhere := detail("IdentityCredential")
		elsewhere.Locations = []string{"https://elsewhere.example.com"}
		minted := detail("IdentityCredential")
		minted.CredentialIdentifiers = []string{"mine"}
		for name, d := range map[string][]oid4vci.AuthorizationDetail{
			"another type":           {other},
			"an unknown config":      {detail("Nope")},
			"one config twice":       {detail("IdentityCredential"), detail("IdentityCredential")},
			"locations elsewhere":    {elsewhere},
			"identifiers of its own": {minted},
		} {
			_, err := redeem(f, "code-2", d...)
			assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
			if t.Failed() {
				t.Logf("case %s", name)
			}
		}
		if got, err := redeem(f, "code-2"); err != nil || len(got.AuthorizationDetails) != 0 {
			t.Errorf("the code after refused requests: %+v, %v; want redeemed, without details", got, err)
		}
	})
	t.Run("a configuration the code doesn't grant", func(t *testing.T) {
		f := newFixture(t, false)
		r := record(f)
		r.Scopes = []string{"another_scope"}
		f.issue(t, "code-3", r)
		_, err := redeem(f, "code-3", detail("IdentityCredential"))
		assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
	})
}

// ParseAuthorizationDetails reads the form parameter: none, or a
// non-empty JSON array of objects.
func TestParseAuthorizationDetails(t *testing.T) {
	if got, err := issuer.ParseAuthorizationDetails(""); err != nil || got != nil {
		t.Errorf(`"": %v, %v`, got, err)
	}
	got, err := issuer.ParseAuthorizationDetails(`[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example.com"]}]`)
	if err != nil || len(got) != 1 || got[0].CredentialConfigurationID != "pid" || len(got[0].Locations) != 1 {
		t.Errorf("one detail: %+v, %v", got, err)
	}
	for _, bad := range []string{"[]", "{}", "not json"} {
		_, err := issuer.ParseAuthorizationDetails(bad)
		assertIssuerError(t, err, issuer.ErrorInvalidAuthorizationDetails)
	}
}
