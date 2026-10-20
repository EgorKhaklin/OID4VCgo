package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
)

// NonceResult is returned by a successful RequestNonce.
type NonceResult struct {
	// CNonce is the fresh challenge (§7.2) — pass it to GenerateProof.
	CNonce string

	// DPoPNonce is the DPoP nonce the response's DPoP-Nonce header
	// carried, if any: §7.2 has the Wallet use it "in the DPoP proof
	// when presenting an access token at the Credential Endpoint". Hand
	// it to a ProtectedResourceClient that implements DPoPNonceUser.
	DPoPNonce string
}

// DPoPNonceUser is a ProtectedResourceClient that can be handed a DPoP
// nonce for a resource before its next request there: DPoPResourceClient
// is one, and so is fapigo/client's ResourceClient. A wrong or stale
// nonce costs only the challenge and retry such a client already
// handles.
type DPoPNonceUser interface {
	UseDPoPNonce(ctx context.Context, resource *url.URL, nonce string)
}

// RequestNonce implements the Nonce Endpoint's own client side (§7.1):
// an unauthenticated HTTP POST with an empty body. The Nonce Endpoint
// is not a protected resource (§7.1) — no access token or DPoP proof
// is needed to call it.
func (w *Wallet) RequestNonce(ctx context.Context, endpoint fapi.URL) (NonceResult, error) {
	target := endpoint.URL()
	res, err := w.fetcher.Post(ctx, fapihttp.PostRequest{
		URL: &target,
		// The Nonce Request has no body (§7.1's own example: "Content-Length: 0").
		// A Content-Type is still set — fapihttp.Post requires one, and no
		// real server rejects an empty POST body over a stated
		// application/json type.
		ContentType:         "application/json",
		ExpectedContentType: "application/json",
	})
	if err != nil {
		return NonceResult{}, fmt.Errorf("wallet: request nonce: %w", err)
	}

	var body struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		return NonceResult{}, fmt.Errorf("wallet: request nonce: decode response: %w", err)
	}
	if body.CNonce == "" {
		return NonceResult{}, fmt.Errorf("wallet: request nonce: response is missing c_nonce")
	}
	return NonceResult{CNonce: body.CNonce, DPoPNonce: res.Header.Get("DPoP-Nonce")}, nil
}
