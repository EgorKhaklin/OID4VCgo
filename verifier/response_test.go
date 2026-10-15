package verifier_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestParseDirectPostJWTResponse drives a real round trip: build a
// real Authorization Request (to get a real response-encryption
// public key), encrypt a JSON response with it via internal/jwe's own
// production Encrypt (standing in for what a real Wallet would do),
// then parse it back via ParseDirectPostJWTResponse.
func TestParseDirectPostJWTResponse(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"vp_token": map[string][]string{"identity_credential": {"sdjwt-compact-string"}},
		"state":    "state-1",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	responseJWE, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM, body, jwe.EncryptOptions{})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	parsed, err := v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	if err != nil {
		t.Fatalf("ParseDirectPostJWTResponse: %v", err)
	}
	if parsed.State != "state-1" {
		t.Errorf("State = %q, want state-1", parsed.State)
	}
	if len(parsed.VPToken["identity_credential"]) != 1 || parsed.VPToken["identity_credential"][0] != "sdjwt-compact-string" {
		t.Errorf("VPToken = %v", parsed.VPToken)
	}
}

func TestParseDirectPostJWTResponseReturnsResponseError(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"error": "access_denied", "error_description": "user declined", "state": "state-1",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	responseJWE, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM, body, jwe.EncryptOptions{})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	_, err = v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	var respErr *verifier.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatalf("error = %v, want *verifier.ResponseError", err)
	}
	if respErr.Code != "access_denied" || respErr.Description != "user declined" || respErr.State != "state-1" {
		t.Errorf("ResponseError = %+v", respErr)
	}
}

func TestParseDirectPostJWTResponseRejectsMissingVPToken(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	body, err := json.Marshal(map[string]any{"state": "state-1"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	responseJWE, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM, body, jwe.EncryptOptions{})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	if _, err := v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey); err == nil {
		t.Fatalf("ParseDirectPostJWTResponse = nil error, want error")
	}
}

// TestResponseError_Error covers both of ResponseError.Error's own
// branches (with/without a Description) — found unexercised by any
// existing test in a repo-wide coverage review.
func TestResponseError_Error(t *testing.T) {
	withDescription := &verifier.ResponseError{Code: "access_denied", Description: "user declined"}
	if got, want := withDescription.Error(), `verifier: wallet returned error "access_denied": user declined`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	withoutDescription := &verifier.ResponseError{Code: "access_denied"}
	if got, want := withoutDescription.Error(), `verifier: wallet returned error "access_denied"`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// TestParseDirectPostJWTResponseRejectsCompressedResponse checks a
// zip:DEF response is refused before decryption: this Verifier never
// offers compression, and anyone who sees the Request Object can encrypt
// to its response key, so inflating one would let an unauthenticated
// sender make the Verifier allocate far more than it sent.
func TestParseDirectPostJWTResponseRejectsCompressedResponse(t *testing.T) {
	v := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	compact, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM,
		[]byte(`{"vp_token":{"cred1":["`+strings.Repeat("a", 4096)+`"]}}`), jwe.EncryptOptions{Zip: jwe.DEF})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	if _, err := v.ParseDirectPostJWTResponse(compact, built.ResponseDecryptionKey); err == nil || !strings.Contains(err.Error(), "compressed") {
		t.Fatalf("ParseDirectPostJWTResponse(zip:DEF) error = %v, want a refused compressed response", err)
	}
}

// A response that won't parse is the Wallet's: a *verifier.Error,
// ReasonMalformed. A missing decryption key is the caller's: a plain
// error.
func TestParseDirectPostJWTResponseMalformed(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	encrypt := func(body []byte) string {
		t.Helper()
		s, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM, body, jwe.EncryptOptions{KeyID: "k"})
		if err != nil {
			t.Fatalf("jwe.Encrypt: %v", err)
		}
		return s
	}
	good := encrypt([]byte(`{"vp_token":{"q":["x"]}}`))

	if _, err := v.ParseDirectPostJWTResponse(good, nil); err == nil || errors.As(err, new(*verifier.Error)) {
		t.Errorf("no decryption key: %v, want a plain error", err)
	}
	for name, response := range map[string]string{
		"not JSON":        encrypt([]byte("not json")),
		"no vp_token":     encrypt([]byte(`{"state":"s"}`)),
		"empty vp_token":  encrypt([]byte(`{"vp_token":{}}`)),
		"not a JWE":       "a.b.c",
		"wrong recipient": good[:len(good)-4] + "AAAA",
	} {
		_, err := v.ParseDirectPostJWTResponse(response, built.ResponseDecryptionKey)
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed {
			t.Errorf("%s: %v, want ReasonMalformed", name, err)
		}
	}

	if _, err := verifier.ResponseKeyID(encrypt([]byte(`{}`))); err != nil {
		t.Errorf("ResponseKeyID with a kid: %v", err)
	}
	noKID, err := jwe.Encrypt(&built.ResponseDecryptionKey.PublicKey, jwe.A128GCM, []byte(`{}`), jwe.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, response := range map[string]string{"no kid": noKID, "not a JWE": "a.b.c"} {
		_, err := verifier.ResponseKeyID(response)
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed {
			t.Errorf("ResponseKeyID, %s: %v, want ReasonMalformed", name, err)
		}
	}
}
