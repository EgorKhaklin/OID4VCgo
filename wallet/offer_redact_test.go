package wallet_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A malformed offer link's error never carries the link, which may hold
// a pre-authorized code; it's still a *url.Error, so callers can tell a
// malformed link.
func TestResolveCredentialOffer_ErrorOmitsTheLink(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("no request expected") })
	_, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer=SECRET-CODE\x01")
	var urlErr *url.Error
	if err == nil || strings.Contains(err.Error(), "SECRET-CODE") || !errors.As(err, &urlErr) {
		t.Errorf("err = %v; want a *url.Error without the link", err)
	}
}
