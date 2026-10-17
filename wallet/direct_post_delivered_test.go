package wallet_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// Once the Verifier replies, whatever it replies, the response has
// reached it: SubmitDirectPostResponse's error matches
// ErrResponseDelivered. A request that never got a reply doesn't.
func TestSubmitDirectPostResponse_ErrResponseDelivered(t *testing.T) {
	for name, tc := range map[string]struct {
		handler   http.HandlerFunc
		delivered bool
	}{
		"a 400 refusal": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		}, true},
		"a redirect": {func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }, true},
		"JSON it can't parse": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"redirect_uri":`))
		}, true},
		"a redirect_uri that isn't https": {func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"redirect_uri":"http://verifier.example/done"}`))
		}, true},
	} {
		srv := httptest.NewServer(tc.handler)
		_, err := wallet.SubmitDirectPostResponse(context.Background(), srv.Client(), srv.URL+"/response", "jwe")
		srv.Close()
		if err == nil || errors.Is(err, wallet.ErrResponseDelivered) != tc.delivered {
			t.Errorf("%s: %v, want delivered = %v", name, err, tc.delivered)
		}
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	if _, err := wallet.SubmitDirectPostResponse(context.Background(), srv.Client(), srv.URL+"/response", "jwe"); err == nil || errors.Is(err, wallet.ErrResponseDelivered) {
		t.Errorf("no server: %v, want an error not marked delivered", err)
	}
}
