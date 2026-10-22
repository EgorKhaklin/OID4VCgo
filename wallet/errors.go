package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Endpoint is which of an issuer's endpoints answered with an Error.
type Endpoint string

const (
	// EndpointToken is the Authorization Server's token endpoint: a
	// pre-authorized code, refresh or revocation request. Its codes are
	// RFC 6749 §5.2's and OpenID4VCI §6.3's: invalid_grant, invalid_request,
	// use_dpop_nonce, …
	EndpointToken Endpoint = "token"
	// EndpointCredential is the Credential Endpoint, or the Deferred
	// Credential Endpoint, which answers the same way (§8.3.1, §9.3):
	// the codes issuer.ErrorCode names (invalid_proof,
	// invalid_credential_request, …).
	EndpointCredential Endpoint = "credential"
	// EndpointNotification is the Notification Endpoint (§11.3).
	EndpointNotification Endpoint = "notification"
)

// Error is an error response from an issuer's endpoint, parsed from a
// non-2xx HTTP response: Endpoint says which, and so which set of codes
// Code is one of. Code is kept as a plain string, not issuer.ErrorCode,
// so this package doesn't need to import issuer just to describe a
// value it only ever reads off the wire.
type Error struct {
	Endpoint    Endpoint
	HTTPStatus  int
	Code        string
	Description string
}

// Error implements the error interface.
func (e *Error) Error() string {
	endpoint := e.Endpoint
	if endpoint == "" {
		endpoint = EndpointCredential
	}
	if e.Description != "" {
		return fmt.Sprintf("wallet: %s error response: %s: %s", endpoint, e.Code, e.Description)
	}
	return fmt.Sprintf("wallet: %s error response: %s", endpoint, e.Code)
}

// parseError builds an Error from a non-2xx Credential Endpoint
// response — the {"error": ..., "error_description": ...} body
// §8.3.1.2 defines. If body isn't valid JSON (a proxy's own HTML error
// page, for instance), Code is left empty and the raw HTTP status is
// still reported.
func parseError(endpoint Endpoint, httpStatus int, body []byte) *Error {
	return parseErrorWithHeader(endpoint, httpStatus, nil, body)
}

// parseErrorWithHeader is parseError, falling back to an RFC 6750 §3
// (or RFC 9449 §7.1) WWW-Authenticate challenge's error and
// error_description when the body carries none: a protected resource's
// authorization error is defined in the header, with no body required
// (OpenID4VCI §8.3.1.1).
func parseErrorWithHeader(endpoint Endpoint, httpStatus int, header http.Header, body []byte) *Error {
	var wire struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &wire)
	if wire.Error == "" {
		for _, challenge := range header.Values("WWW-Authenticate") {
			if code := challengeParam(challenge, "error"); code != "" {
				wire.Error, wire.ErrorDescription = code, challengeParam(challenge, "error_description")
				break
			}
		}
	}
	// The issuer's text ends up in logs and in front of the holder.
	return &Error{Endpoint: endpoint, HTTPStatus: httpStatus, Code: sanitizeReplyText(wire.Error), Description: sanitizeReplyText(wire.ErrorDescription)}
}

// challengeParam is the value of the auth-param name in an RFC 9110
// §11.6.1 challenge (`DPoP error="invalid_token", ...`), quoted or a
// token, "" when absent.
func challengeParam(challenge, name string) string {
	_, params, _ := strings.Cut(strings.TrimSpace(challenge), " ")
	for params != "" {
		params = strings.TrimLeft(params, " ,")
		key, rest, ok := strings.Cut(params, "=")
		if !ok {
			return ""
		}
		key = strings.TrimSpace(key)
		var value string
		value, params = challengeParamValue(strings.TrimLeft(rest, " "))
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// challengeParamValue splits rest, which starts with an auth-param's
// value, into that value, unquoted if it's a quoted-string, and what
// follows it.
func challengeParamValue(rest string) (value, remainder string) {
	if !strings.HasPrefix(rest, `"`) {
		value, remainder, _ = strings.Cut(rest, ",")
		return strings.TrimSpace(value), remainder
	}
	var b strings.Builder
	i := 1
	for ; i < len(rest) && rest[i] != '"'; i++ {
		if rest[i] == '\\' && i+1 < len(rest) {
			i++
		}
		b.WriteByte(rest[i])
	}
	return b.String(), rest[min(i+1, len(rest)):]
}
