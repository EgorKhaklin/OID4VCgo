package verifier_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// reply is a response endpoint's whole answer: status and body.
type reply struct {
	status int
	body   string
}

func postResponse(t *testing.T, endpoint string, form url.Values) reply {
	t.Helper()
	r, err := http.PostForm(endpoint, form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return reply{r.StatusCode, string(body)}
}

// TestTransactions_ResponseEndpointIsNoCompletionOracle: anyone holding
// a request's QR code has its response key and state, and can post to
// the response endpoint. Its reply mustn't tell them whether the holder
// has presented: an answer that fails is refused alike whether the
// request is pending, answered, closed, expired or unknown, and an
// error response carrying the request's state is acknowledged alike
// whether the request is pending or not.
func TestTransactions_ResponseEndpointIsNoCompletionOracle(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	srv := httptest.NewServer(f.txs.ResponseHandler())
	defer srv.Close()

	type probes struct{ forged, encErr, plainErr reply }
	// prepare reads what a probe of begun needs from its Request Object,
	// as anyone holding its QR code can while it's pending.
	prepare := func(begun verifier.Begun) func() probes {
		t.Helper()
		forged := url.Values{"response": {forgedJWE(t, f.responseKeyIDOf(begun), map[string]any{"alg": "ECDH-ES", "enc": "A128GCM"})}}
		encErr := url.Values{"response": {f.errorAnswer(begun, "access_denied", "")}}
		plainErr := url.Values{"error": {"access_denied"}, "state": {f.stateOf(begun)}}
		return func() probes {
			return probes{postResponse(t, srv.URL, forged), postResponse(t, srv.URL, encErr), postResponse(t, srv.URL, plainErr)}
		}
	}

	for _, sameDevice := range []bool{false, true} {
		want := prepare(f.begin("browser-binding-A", sameDevice))()
		if want.forged.status != http.StatusBadRequest || want.encErr.status != http.StatusOK || want.plainErr.status != http.StatusOK {
			t.Fatalf("sameDevice %v: pending replies %+v", sameDevice, want)
		}

		answered := f.begin("browser-binding-A", sameDevice)
		probeAnswered := prepare(answered)
		if _, err := f.txs.HandleResponse(ctx, f.answer(answered, nil)); err != nil {
			t.Fatalf("HandleResponse: %v", err)
		}
		closed := f.begin("browser-binding-A", sameDevice)
		probeClosed := prepare(closed)
		if err := f.txs.Close(ctx, closed.ID); err != nil {
			t.Fatal(err)
		}
		probeExpired := prepare(f.begin("browser-binding-A", sameDevice))
		for name, probe := range map[string]func() probes{"answered": probeAnswered, "closed": probeClosed} {
			if got := probe(); got != want {
				t.Errorf("sameDevice %v, %s: replies %+v, want the pending request's %+v", sameDevice, name, got, want)
			}
		}
		// The request object is still served once answered or closed.
		for name, begun := range map[string]verifier.Begun{"answered": answered, "closed": closed} {
			if _, err := f.txs.RequestObject(ctx, begun.ID); err != nil {
				t.Errorf("sameDevice %v, %s: RequestObject: %v", sameDevice, name, err)
			}
		}
		f.now = f.now.Add(time.Hour)
		if got := probeExpired(); got.forged != want.forged {
			t.Errorf("sameDevice %v, expired: refusal %+v, want the pending request's %+v", sameDevice, got.forged, want.forged)
		}
		f.now = f.now.Add(-time.Hour)

		// A genuine Wallet resending its answer after it completed the
		// request gets the same refusal as a forged answer.
		resent := f.begin("browser-binding-A", sameDevice)
		jwe := f.answer(resent, nil)
		if r := postResponse(t, srv.URL, url.Values{"response": {jwe}}); r.status != http.StatusOK {
			t.Fatalf("sameDevice %v: first answer %+v", sameDevice, r)
		}
		if r := postResponse(t, srv.URL, url.Values{"response": {jwe}}); r != want.forged {
			t.Errorf("sameDevice %v: resent answer %+v, want %+v", sameDevice, r, want.forged)
		}

		// Acknowledging an error response for a request that's no longer
		// pending doesn't record it there.
		if view, err := f.txs.Lookup(ctx, answered.ID, "browser-binding-A"); err != nil || view.LastError != "" || view.Status == verifier.TransactionPending {
			t.Errorf("sameDevice %v: answered request after the probes: %+v, %v", sameDevice, view, err)
		}
	}
}
