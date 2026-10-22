package wallet_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// requestURIPostServer plays a Verifier's request_uri endpoint for
// request_uri_method=post (OpenID4VP 1.0 §5.10.1): it reads the form
// the Wallet posts, and answers with a Request Object carrying echo as
// its wallet_nonce, or the posted one when echo is empty.
func requestURIPostServer(t *testing.T, v *verifier.Verifier, echo string, posted *url.Values) func(*http.Request) (*http.Response, error) {
	t.Helper()
	return func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", req.Method)
		}
		if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want a form", got)
		}
		if got := req.Header.Get("Accept"); got != "application/oauth-authz-req+jwt" {
			t.Errorf("Accept = %q, want application/oauth-authz-req+jwt", got)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatalf("parse form: %v", err)
		}
		*posted = form
		nonce := echo
		if nonce == "" {
			nonce = form.Get("wallet_nonce")
		}
		built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t), State: "s1", WalletNonce: nonce})
		if err != nil {
			t.Fatalf("BuildAuthorizationRequest: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(built.RequestObject)),
			Header:     http.Header{"Content-Type": []string{"application/oauth-authz-req+jwt"}},
		}, nil
	}
}

const testWalletMetadata = `{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}}}`

// FetchAuthorizationRequestPost posts wallet_nonce and wallet_metadata
// as a form and accepts the Request Object that echoes the nonce.
func TestFetchAuthorizationRequestPost(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	var posted url.Values
	w := newTestWalletTrusting(t, trust, requestURIPostServer(t, v, "", &posted))

	got, err := w.FetchAuthorizationRequestPost(context.Background(), "http://localhost/request/abc", clientID, "wn-1", json.RawMessage(testWalletMetadata))
	if err != nil {
		t.Fatalf("FetchAuthorizationRequestPost: %v", err)
	}
	if got.ClientID != clientID || got.State != "s1" {
		t.Errorf("got client_id %q, state %q", got.ClientID, got.State)
	}
	if posted.Get("wallet_nonce") != "wn-1" || posted.Get("wallet_metadata") != testWalletMetadata {
		t.Errorf("posted form = %v, want wallet_nonce and wallet_metadata", posted)
	}
}

// A Request Object that doesn't echo the wallet_nonce posted for it,
// built for another fetch, is refused.
func TestFetchAuthorizationRequestPost_RefusesOtherWalletNonce(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	var posted url.Values
	w := newTestWalletTrusting(t, trust, requestURIPostServer(t, v, "wn-other", &posted))

	if _, err := w.FetchAuthorizationRequestPost(context.Background(), "http://localhost/request/abc", clientID, "wn-1", nil); err == nil || !strings.Contains(err.Error(), "wallet_nonce") {
		t.Fatalf("error = %v, want a wallet_nonce mismatch", err)
	}
	if _, sent := posted["wallet_metadata"]; sent {
		t.Error("sent wallet_metadata when none was given")
	}
}

// The request isn't sent without a VerifierTrust, a wallet_nonce, or
// with wallet_metadata that isn't a JSON object.
func TestFetchAuthorizationRequestPost_RefusesBeforeSending(t *testing.T) {
	_, _, trust := newTestVerifier(t)
	refuse := func(*http.Request) (*http.Response, error) {
		t.Fatal("posted to request_uri")
		return nil, nil
	}
	untrusting := newTestWallet(t, refuse)
	trusting := newTestWalletTrusting(t, trust, refuse)
	for name, tc := range map[string]struct {
		w        *wallet.Wallet
		nonce    string
		metadata json.RawMessage
		want     string
	}{
		"no VerifierTrust":  {untrusting, "wn-1", nil, "VerifierTrust is required"},
		"no wallet_nonce":   {trusting, "", nil, "wallet_nonce is required"},
		"metadata array":    {trusting, "wn-1", json.RawMessage(`[]`), "JSON object"},
		"metadata null":     {trusting, "wn-1", json.RawMessage(`null`), "JSON object"},
		"metadata not JSON": {trusting, "wn-1", json.RawMessage(`{`), "JSON object"},
	} {
		_, err := tc.w.FetchAuthorizationRequestPost(context.Background(), "http://localhost/request/abc", "x509_hash:abc", tc.nonce, tc.metadata)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
}

// §5.10.1 fixes the response's media type: application/jwt, which a
// GET request_uri may answer with, isn't accepted for a POST.
func TestFetchAuthorizationRequestPost_RequiresRequestObjectMediaType(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	var posted url.Values
	serve := requestURIPostServer(t, v, "", &posted)
	w := newTestWalletTrusting(t, trust, func(req *http.Request) (*http.Response, error) {
		res, err := serve(req)
		if res != nil {
			res.Header.Set("Content-Type", "application/jwt")
		}
		return res, err
	})
	if _, err := w.FetchAuthorizationRequestPost(context.Background(), "http://localhost/request/abc", clientID, "wn-1", nil); err == nil {
		t.Fatal("accepted an application/jwt response to a request_uri POST")
	}
}

// (*Wallet).ParseAuthorizationRequest verifies with the Wallet's own
// VerifierTrust, and checks the wallet_nonce it's given.
func TestWalletParseAuthorizationRequest(t *testing.T) {
	v, clientID, trust := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t), WalletNonce: "wn-1"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	none := func(*http.Request) (*http.Response, error) {
		t.Fatal("unexpected HTTP request")
		return nil, nil
	}
	w := newTestWalletTrusting(t, trust, none)
	if _, err := w.ParseAuthorizationRequest(built.RequestObject, clientID, "wn-1"); err != nil {
		t.Errorf("ParseAuthorizationRequest: %v", err)
	}
	if _, err := w.ParseAuthorizationRequest(built.RequestObject, clientID, "wn-other"); err == nil {
		t.Error("ParseAuthorizationRequest accepted another wallet_nonce")
	}

	_, _, otherTrust := newTestVerifier(t)
	if _, err := newTestWalletTrusting(t, otherTrust, none).ParseAuthorizationRequest(built.RequestObject, clientID, ""); err == nil {
		t.Error("ParseAuthorizationRequest accepted a Verifier its VerifierTrust doesn't")
	}
	if _, err := newTestWallet(t, none).ParseAuthorizationRequest(built.RequestObject, clientID, ""); err == nil || !strings.Contains(err.Error(), "VerifierTrust is required") {
		t.Errorf("without VerifierTrust: %v, want it required", err)
	}
}
