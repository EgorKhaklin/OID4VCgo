package wallet

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

// With no HTTP client, the Wallet builds fapihttp's hardened one: it
// won't dial a loopback address unless Config.Fetch allows it.
func TestWalletHTTPClient_DefaultIsHardened(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer srv.Close()
	fetch := fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second}

	hardened, err := walletHTTPClient(Config{Fetch: fetch}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if res, err := hardened.Do(req); err == nil {
		_ = res.Body.Close()
		t.Fatal("the default client dialed a loopback address")
	}

	fetch.AllowLoopbackHosts, fetch.AllowLoopbackHTTP = true, true
	development, err := walletHTTPClient(Config{Fetch: fetch}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL, nil)
	res, err := development.Do(req)
	if err != nil {
		t.Fatalf("with loopback allowed: %v", err)
	}
	_ = res.Body.Close()
}

// A given *http.Client is used through a copy that follows no
// redirect: a DPoP proof or access token isn't resent elsewhere. The
// caller's client is left as it was.
func TestWalletHTTPClient_FollowsNoRedirect(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	given := &http.Client{Timeout: 5 * time.Second}
	client, err := walletHTTPClient(Config{}, given)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	req.Header.Set("DPoP", "proof")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if followed || res.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("status %d, followed %v; want the redirect returned, not followed", res.StatusCode, followed)
	}
	if given.CheckRedirect != nil {
		t.Error("the caller's client was changed")
	}
}
