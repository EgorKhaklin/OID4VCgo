package issuer_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// Error responses (RFC 6749 §5.2 for the Token Endpoint's) and Deferred
// Credential Responses are never cached.
func TestResponses_NoStore(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"other"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID, SDJWTClaims: testSDJWTClaims(),
	})
	rec := httptest.NewRecorder()
	issuer.WriteError(rec, err)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("error response Cache-Control = %q", got)
	}
	rec = httptest.NewRecorder()
	issuer.DeferredCredentialResult{TransactionID: "t", Interval: time.Second}.WriteJSON(rec)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("deferred response Cache-Control = %q", got)
	}
}
