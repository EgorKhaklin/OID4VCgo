package wallet_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// fapigo/client's ResourceClient takes a nonce the same way, so
// walletflow hands one to either.
var _ wallet.DPoPNonceUser = (*client.ResourceClient)(nil)

// TestRequestNonce_ReturnsTheDPoPNonce: OpenID4VCI 1.0 §7.2 lets the
// Nonce Response carry a DPoP nonce in its DPoP-Nonce header, for the
// Credential Request; RequestNonce returns it.
func TestRequestNonce_ReturnsTheDPoPNonce(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		res := jsonResponse([]byte(`{"c_nonce":"fresh-nonce"}`))
		res.Header.Set("DPoP-Nonce", "dpop-nonce-1")
		return res, nil
	})
	result, err := w.RequestNonce(context.Background(), testNonceEndpoint(t))
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	if result.DPoPNonce != "dpop-nonce-1" {
		t.Errorf("DPoPNonce = %q, want dpop-nonce-1", result.DPoPNonce)
	}
}

// TestDPoPResourceClient_UseDPoPNonce: a nonce handed to the client is
// presented by its next request, which then isn't challenged.
func TestDPoPResourceClient_UseDPoPNonce(t *testing.T) {
	var proofs []string
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		proofs = append(proofs, req.Header.Get("DPoP"))
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})
	rc := w.DPoPResourceClient(fapi.NewSecret("tok-1"), testP256Key(t))
	user, ok := rc.(wallet.DPoPNonceUser)
	if !ok {
		t.Fatal("DPoPResourceClient doesn't implement DPoPNonceUser")
	}
	endpoint, _ := url.Parse("https://issuer.example.com/credential")
	user.UseDPoPNonce(context.Background(), endpoint, "from-nonce-response")
	req, _ := http.NewRequest(http.MethodPost, endpoint.String(), strings.NewReader("{}"))
	if _, err := rc.Do(context.Background(), req); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("sent %d requests, want 1", len(proofs))
	}
	if _, claims := jwtParts(t, proofs[0]); claims["nonce"] != "from-nonce-response" {
		t.Errorf("proof nonce = %v, want from-nonce-response", claims["nonce"])
	}
}

// TestFetchCredentialIssuerMetadata_SendsAcceptLanguage: §12.2.2
// recommends the Wallet send Accept-Language; Config.Locales becomes
// one, most preferred first, leaving out a tag that isn't one.
func TestFetchCredentialIssuerMetadata_SendsAcceptLanguage(t *testing.T) {
	for _, tc := range []struct {
		locales []string
		want    string
	}{
		{[]string{"de-CH", "de", "en"}, "de-CH, de;q=0.9, en;q=0.8"},
		{[]string{"fr", "bad tag", "fr", "en\r\nX: y"}, "fr"},
		{nil, ""},
	} {
		var got string
		var ts *httptest.Server
		ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Accept-Language")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"credential_issuer":"` + ts.URL + `","credential_endpoint":"` + ts.URL + `/credential","credential_configurations_supported":{}}`))
		}))
		cfg := validConfig()
		cfg.Locales = tc.locales
		deps := validDependencies()
		deps.HTTP = http.DefaultClient
		w, err := wallet.New(cfg, deps)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.FetchCredentialIssuerMetadata(context.Background(), ts.URL)
		ts.Close()
		if got != tc.want {
			t.Errorf("Locales %q: Accept-Language = %q, want %q", tc.locales, got, tc.want)
		}
	}
}
