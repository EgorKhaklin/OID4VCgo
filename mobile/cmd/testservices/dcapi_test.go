package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func newDCAPIRequests(t *testing.T, origin string) (*dcapiRequests, *http.ServeMux) {
	t.Helper()
	env, err := walletflowtest.New(walletflowtest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	v, err := env.StartVerifier()
	if err != nil {
		t.Fatal(err)
	}
	d := &dcapiRequests{v: v, origin: origin, requests: map[string]*walletflowtest.DCAPIRequest{}, results: map[string]map[string]any{}}
	mux := http.NewServeMux()
	d.routes(mux, env)
	return d, mux
}

// TestDCAPIRequest_BoundToConfiguredOrigin: a request is bound to the
// configured origin whatever Host it came in under, so a page relaying
// requests from elsewhere can't have them bound to its own origin.
func TestDCAPIRequest_BoundToConfiguredOrigin(t *testing.T) {
	const origin = "https://127.0.0.1:8600"
	d, mux := newDCAPIRequests(t, origin)
	r := httptest.NewRequest(http.MethodPost, "/dcapi/request", nil)
	r.Host = "relay.example"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /dcapi/request = %d: %s", w.Code, w.Body)
	}
	if req := d.requests["1"]; req == nil || req.Origin != origin {
		t.Errorf("request bound to %+v, want %s", req, origin)
	}
}

// TestDCAPIRequest_RefusedWithoutOrigin: with no origin configured, no
// request is made rather than one bound to the request's Host.
func TestDCAPIRequest_RefusedWithoutOrigin(t *testing.T) {
	d, mux := newDCAPIRequests(t, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dcapi/request", nil))
	if w.Code == http.StatusOK || len(d.requests) != 0 {
		t.Errorf("POST /dcapi/request without an origin = %d, %d requests; want it refused", w.Code, len(d.requests))
	}
}
