package wallet_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A client from fapihttp.NewClient, as Dependencies.HTTP documents, has
// no Timeout of its own. The requests the Wallet sends through it
// directly, not through its fetcher (here the Token Request), still end
// after Config.Fetch.RequestTimeout when the server stalls, not only
// when ctx does.
func TestNew_GivenClientTimesOutAfterRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select { // never finish the body
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	hc, err := fapihttp.NewClient(fapihttp.TransportConfig{DialTimeout: time.Second, TLSHandshakeTimeout: time.Second, RootCAs: roots, AllowLoopbackHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: "ES256",
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 200 * time.Millisecond, AllowLoopbackHosts: true},
	}, wallet.Dependencies{HTTP: hc, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if hc.Timeout != 0 {
		t.Fatalf("the given client's Timeout was changed to %v", hc.Timeout)
	}
	endpoint, err := fapi.ParseEndpointURL(srv.URL + "/token")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err = w.RequestPreAuthorizedCodeToken(ctx, endpoint, wallet.PreAuthorizedCodeTokenRequest{PreAuthorizedCode: "c", DPoPKey: testP256Key(t)})
	if err == nil {
		t.Fatal("RequestPreAuthorizedCodeToken = nil error, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("returned after %v, want about Fetch.RequestTimeout", elapsed)
	}
}
