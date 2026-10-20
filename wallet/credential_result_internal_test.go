package wallet

import (
	"net/http"
	"testing"
	"time"
)

// An error a protected resource puts only in its WWW-Authenticate
// challenge (RFC 6750 §3, RFC 9449 §7.1) is read from there.
func TestParseErrorWithHeader(t *testing.T) {
	for challenge, want := range map[string]string{
		`DPoP error="invalid_token", error_description="expired"`:        "invalid_token",
		`Bearer realm="x", error="insufficient_scope"`:                   "insufficient_scope",
		`DPoP algs="ES256", error=use_dpop_nonce`:                        "use_dpop_nonce",
		`Bearer error="invalid_token", error_description="a \"quoted\""`: "invalid_token",
	} {
		h := http.Header{"Www-Authenticate": {challenge}}
		if got := parseErrorWithHeader(EndpointCredential, 401, h, nil).Code; got != want {
			t.Errorf("%s: Code = %q, want %q", challenge, got, want)
		}
	}
	h := http.Header{"Www-Authenticate": {`Bearer error="invalid_token", error_description="a \"quoted\" one"`}}
	if got := parseErrorWithHeader(EndpointCredential, 401, h, nil).Description; got != `a "quoted" one` {
		t.Errorf("Description = %q", got)
	}
	// A body's error wins over the header's.
	if got := parseErrorWithHeader(EndpointCredential, 401, h, []byte(`{"error":"invalid_nonce"}`)).Code; got != "invalid_nonce" {
		t.Errorf("Code = %q, want the body's", got)
	}
}

// interval is "a positive number" of seconds (OpenID4VCI §8.3): a
// fractional one is rounded up, to at least a second; a response
// carrying both credentials and a transaction_id, or neither, is
// refused.
func TestParseCredentialResult(t *testing.T) {
	for body, want := range map[string]time.Duration{
		`{"transaction_id":"t","interval":1.5}`:    2 * time.Second,
		`{"transaction_id":"t","interval":3600.0}`: time.Hour,
		`{"transaction_id":"t","interval":0.2}`:    time.Second,
	} {
		got, err := parseCredentialResult(http.StatusAccepted, nil, []byte(body))
		if err != nil || got.Interval != want || got.TransactionID != "t" {
			t.Errorf("%s: %+v, %v; want interval %s", body, got, err, want)
		}
	}
	for _, body := range []string{`{"credentials":[{"credential":"c"}],"transaction_id":"t"}`, `{}`} {
		if _, err := parseCredentialResult(http.StatusOK, nil, []byte(body)); err == nil {
			t.Errorf("%s: accepted", body)
		}
	}
}
