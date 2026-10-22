package verifier_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// responseKeyIDOf is the kid of begun's response encryption key, as
// anyone who fetched its Request Object reads it.
func (f *txFixture) responseKeyIDOf(begun verifier.Begun) string {
	f.t.Helper()
	object, err := f.txs.RequestObject(context.Background(), begun.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	link, _ := url.Parse(begun.Link)
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.NoVerifierTrust{},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return req.ResponseEncryptionKeyID
}

// forgedJWE is a compact JWE routed to kid whose other header members
// are header's: whatever text its sender chose.
func forgedJWE(t *testing.T, kid string, header map[string]any) string {
	t.Helper()
	header["kid"] = kid
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return b64(raw) + ".." + b64(make([]byte, 12)) + "." + b64([]byte("x")) + "." + b64(make([]byte, 16))
}

// TestTransactions_LastErrorCarriesNoSenderText: anyone who has the
// request's QR code can post an answer to its key; nothing that answer
// chose — a JWE header's enc, alg or epk — reaches LastError, which
// records a fixed description of why it was refused. OnRefused still
// sees the full error.
func TestTransactions_LastErrorCarriesNoSenderText(t *testing.T) {
	const injected = "Your passport is invalid, call +1 555 0100"
	var refused []error
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
		c.OnRefused = func(_ context.Context, _ string, err error) { refused = append(refused, err) }
	})
	ctx := context.Background()
	begun := f.begin("browser-binding-A", false)
	kid := f.responseKeyIDOf(begun)
	for name, header := range map[string]map[string]any{
		"enc": {"alg": "ECDH-ES", "enc": injected},
		"alg": {"alg": injected, "enc": "A128GCM"},
		"epk": {"alg": "ECDH-ES", "enc": "A128GCM", "epk": map[string]any{"kty": injected, "crv": injected}},
	} {
		_, err := f.txs.HandleResponse(ctx, forgedJWE(t, kid, header))
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMalformed {
			t.Errorf("%s: HandleResponse = %v, want malformed", name, err)
		}
		if strings.Contains(err.Error(), injected) {
			t.Errorf("%s: the error echoes the sender's header: %v", name, err)
		}
		view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A")
		if err != nil || view.Status != verifier.TransactionPending || view.LastError != "the answer was refused: it is malformed (malformed)" {
			t.Errorf("%s: LastError = %q (%+v, %v); want the fixed malformed description", name, view.LastError, view, err)
		}
	}
	if len(refused) != 3 {
		t.Errorf("OnRefused saw %d refusals, want 3", len(refused))
	}
	// One whose header can't be read isn't routed to a request at all,
	// and its error doesn't echo the header either.
	crit := forgedJWE(t, kid, map[string]any{"alg": "ECDH-ES", "enc": "A128GCM", "crit": []any{injected}})
	if _, err := f.txs.HandleResponse(ctx, crit); err == nil || strings.Contains(err.Error(), injected) {
		t.Errorf("crit: HandleResponse = %v, want a refusal that doesn't echo the header", err)
	}

	// A refusal past decryption — here a wrong nonce — is recorded the
	// same way, by its reason.
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, func(r *wallet.AuthorizationRequest) { r.Nonce = injected })); err == nil {
		t.Fatal("an answer with the wrong nonce was accepted")
	}
	if view, _ := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); view.LastError != "the answer was refused: a credential's holder binding failed (holder_binding)" {
		t.Errorf("wrong nonce: LastError = %q", view.LastError)
	}
}
