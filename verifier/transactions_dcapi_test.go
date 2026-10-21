package verifier_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const (
	dcapiOrigin = "https://verifier.example.com"
	testBinding = "browser-binding-A"
)

func (f *txFixture) beginDCAPI(binding string) verifier.BegunDCAPI {
	f.t.Helper()
	begun, err := f.txs.BeginDCAPI(context.Background(), f.query, binding, dcapiOrigin)
	if err != nil {
		f.t.Fatalf("BeginDCAPI: %v", err)
	}
	return begun
}

// dcapiRequest is the wallet's parse of begun's request, as the platform
// hands it over from a page at origin.
func (f *txFixture) dcapiRequest(begun verifier.BegunDCAPI, origin string) wallet.AuthorizationRequest {
	f.t.Helper()
	encoded, err := json.Marshal(begun.Request)
	if err != nil {
		f.t.Fatal(err)
	}
	var page struct {
		Protocol string          `json:"protocol"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(encoded, &page); err != nil {
		f.t.Fatal(err)
	}
	req, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: page.Protocol, Data: page.Data, Origin: origin, VerifierTrust: wallet.NoVerifierTrust{},
	})
	if err != nil {
		f.t.Fatalf("ParseDCAPIRequestData: %v", err)
	}
	return req
}

// dcapiAnswer is the data the platform returns for the wallet's answer
// to begun, presented to a page at origin.
func (f *txFixture) dcapiAnswer(begun verifier.BegunDCAPI, origin string) []byte {
	f.t.Helper()
	req := f.dcapiRequest(begun, dcapiOrigin)
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: req.Query, Credentials: []wallet.HeldCredential{f.held}, Origin: origin, Nonce: req.Nonce,
	})
	if err != nil {
		f.t.Fatalf("PresentCredentials: %v", err)
	}
	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		f.t.Fatalf("BuildDirectPostResponse: %v", err)
	}
	data, err := json.Marshal(map[string]string{"response": response})
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

func TestTransactions_DCAPI(t *testing.T) {
	f := newTxFixture(t, nil)
	ctx := context.Background()
	begun := f.beginDCAPI(testBinding)
	if begun.Request.Protocol != verifier.DCAPIProtocolSigned || begun.Request.Data.Request == "" {
		t.Fatalf("request = %+v", begun.Request)
	}
	// The wallet takes it as a dc_api.jwt request from the page's origin.
	if req := f.dcapiRequest(begun, dcapiOrigin); req.Origin != dcapiOrigin {
		t.Errorf("origin = %q, want %q", req.Origin, dcapiOrigin)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, testBinding); err != nil || view.Status != verifier.TransactionPending {
		t.Fatalf("Lookup before the answer: %+v, %v", view, err)
	}

	view, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin))
	if err != nil {
		t.Fatalf("HandleDCAPIResponse: %v", err)
	}
	if view.Status != verifier.TransactionDone || view.Result == nil || view.Result.Credentials[0].Claims["given_name"] != "Jean" {
		t.Fatalf("view = %+v", view)
	}
	if looked, err := f.txs.Lookup(ctx, begun.ID, testBinding); err != nil || looked.Status != verifier.TransactionDone {
		t.Errorf("Lookup after the answer: %+v, %v", looked, err)
	}
	// Completes once, even with another valid answer.
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionAnswered) {
		t.Errorf("second answer: %v, want ErrTransactionAnswered", err)
	}
}

func TestTransactions_DCAPIRefusals(t *testing.T) {
	f := newTxFixture(t, nil)
	ctx := context.Background()
	begun := f.beginDCAPI(testBinding)

	// Another browser's post is refused, and leaves the request as it was.
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, "another-browser-binding", f.dcapiAnswer(begun, dcapiOrigin)); !errors.Is(err, verifier.ErrWrongBrowser) {
		t.Errorf("another browser: %v, want ErrWrongBrowser", err)
	}
	// Presented to another origin: the wallet bound it to a page this
	// request wasn't made from.
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, "https://attacker.example.com")); err == nil {
		t.Error("an answer bound to another origin was accepted")
	}
	for name, data := range map[string]string{
		"not JSON":          "response",
		"neither member":    `{}`,
		"not a JWE":         `{"response":"x"}`,
		"a wallet's error":  `{"error":"access_denied"}`,
		"over the size cap": `{"response":"` + strings.Repeat("a", verifier.MaxDCAPIResponseBytes) + `"}`,
	} {
		if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, []byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	view, err := f.txs.Lookup(ctx, begun.ID, testBinding)
	if err != nil || view.Status != verifier.TransactionPending {
		t.Fatalf("refused answers closed the request: %+v, %v", view, err)
	}
	if view.LastError == "" {
		t.Error("the refusals left no LastError")
	}
	// Still answerable.
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin)); err != nil {
		t.Errorf("the valid answer after refusals: %v", err)
	}
}

func TestTransactions_DCAPIEncryptedWalletError(t *testing.T) {
	f := newTxFixture(t, nil)
	ctx := context.Background()
	begun := f.beginDCAPI(testBinding)
	req := f.dcapiRequest(begun, dcapiOrigin)
	payload, _ := json.Marshal(map[string]string{"error": "access_denied"})
	compact, err := jwe.Encrypt(req.ResponseEncryptionKey, jwe.Enc(req.ResponseEncryptionEnc), payload, jwe.EncryptOptions{KeyID: req.ResponseEncryptionKeyID})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"response": compact})
	var walletErr *verifier.ResponseError
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, data); !errors.As(err, &walletErr) || walletErr.Code != "access_denied" {
		t.Fatalf("encrypted error: %v, want a *ResponseError access_denied", err)
	}
	if view, _ := f.txs.Lookup(ctx, begun.ID, testBinding); view.Status != verifier.TransactionPending || view.LastError != "an error response arrived: access_denied" {
		t.Errorf("after the error: %+v", view)
	}
}

// The two flows' requests don't cross: a DC API request isn't served at a
// request_uri or answered at the response endpoint, and a redirect
// request isn't answered through HandleDCAPIResponse.
func TestTransactions_DCAPIAndRedirectDontCross(t *testing.T) {
	f := newTxFixture(t, nil)
	ctx := context.Background()
	dc := f.beginDCAPI(testBinding)
	if _, err := f.txs.RequestObject(ctx, dc.ID); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("RequestObject of a DC API request: %v, want ErrTransactionUnknown", err)
	}
	if answered := f.txs.HandleUnencryptedError(ctx, "access_denied", dc.ID+"."); answered.ID != "" {
		t.Errorf("an unencrypted error reached a DC API request: %+v", answered)
	}
	redirect := f.begin(testBinding, false)
	if _, err := f.txs.HandleDCAPIResponse(ctx, redirect.ID, testBinding, f.dcapiAnswer(dc, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("HandleDCAPIResponse of a redirect request: %v, want ErrTransactionUnknown", err)
	}
	// The DC API answer, posted to the response endpoint, routes nowhere.
	var answer struct {
		Response string `json:"response"`
	}
	_ = json.Unmarshal(f.dcapiAnswer(dc, dcapiOrigin), &answer)
	if _, err := f.txs.HandleResponse(ctx, answer.Response); err == nil {
		t.Error("a DC API answer was accepted at the response endpoint")
	}
}

func TestTransactions_DCAPIExpiryAndAccept(t *testing.T) {
	refuse := errors.New("revoked")
	var accepted string
	f := newTxFixture(t, func(cfg *verifier.TransactionsConfig) {
		cfg.Accept = func(_ context.Context, id string, _ verifier.VerifyResponseResult) error {
			if accepted == "" {
				accepted = id
				return refuse
			}
			return nil
		}
	})
	ctx := context.Background()
	begun := f.beginDCAPI(testBinding)
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin)); !errors.Is(err, refuse) || accepted != begun.ID {
		t.Fatalf("Accept's refusal: %v (Accept saw %q)", err, accepted)
	}
	f.now = f.now.Add(11 * time.Minute)
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionExpired) {
		t.Errorf("after the lifetime: %v, want ErrTransactionExpired", err)
	}
}

func TestTransactions_BeginDCAPIValidates(t *testing.T) {
	f := newTxFixture(t, nil)
	ctx := context.Background()
	for name, origin := range map[string]string{
		"empty":          "",
		"a path":         "https://verifier.example.com/",
		"http":           "http://verifier.example.com",
		"no scheme":      "verifier.example.com",
		"with a query":   "https://verifier.example.com?x=1",
		"with userinfo":  "https://u@verifier.example.com",
		"a non-loopback": "http://192.0.2.1:8080",
	} {
		if _, err := f.txs.BeginDCAPI(ctx, f.query, testBinding, origin); err == nil {
			t.Errorf("origin %s (%q): accepted", name, origin)
		}
	}
	if _, err := f.txs.BeginDCAPI(ctx, f.query, testBinding, "http://localhost:8443"); err != nil {
		t.Errorf("loopback http under development: %v", err)
	}
	if _, err := f.txs.BeginDCAPI(ctx, f.query, "short", dcapiOrigin); err == nil {
		t.Error("a short browser binding was accepted")
	}
	mdocQuery := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "m", Format: mdoc.CredentialFormat}}}
	if _, err := f.txs.BeginDCAPI(ctx, mdocQuery, testBinding, dcapiOrigin); err == nil {
		t.Error("a query for a format Verify can't check was accepted")
	}

	// A Verifier for the DC API alone needs no request_uri base; Begin does.
	dcOnly := newTxFixture(t, func(cfg *verifier.TransactionsConfig) { cfg.RequestURIBase = "" })
	dcOnly.beginDCAPI(testBinding)
	if _, err := dcOnly.txs.Begin(ctx, dcOnly.query, testBinding, false); err == nil {
		t.Error("Begin without a request_uri base: accepted")
	}
}
