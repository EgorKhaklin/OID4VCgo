package issuer_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// dpopNonceFixture is a pre-authorized code fixture with DPoP nonces
// whose clock the test moves.
type dpopNonceFixture struct {
	preAuthorizedCodeFixture
	nonces *fakeDPoPNonceStore
	mu     sync.Mutex
	clock  time.Time
	issued int
}

func newDPoPNonceFixture(t *testing.T, lifetime time.Duration) *dpopNonceFixture {
	t.Helper()
	d := &dpopNonceFixture{nonces: newFakeDPoPNonceStore()}
	d.preAuthorizedCodeFixture = newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.Limits.DPoPNonceLifetime = lifetime
		deps.DPoPNonces = d.nonces
		d.clock = deps.Clock.Now()
		deps.Clock = issuer.ClockFunc(d.clockNow)
	})
	return d
}

func (d *dpopNonceFixture) clockNow() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.clock
}

func (d *dpopNonceFixture) setNow(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clock = at
}

// request builds a Token Request for a freshly issued pre-authorized
// code, with a DPoP proof made now carrying nonce.
func (d *dpopNonceFixture) request(t *testing.T, nonce string) issuer.ExchangePreAuthorizedCodeRequest {
	t.Helper()
	d.issued++
	code := fmt.Sprint("code-", d.issued)
	at := d.clockNow()
	d.issue(t, code, issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: at.Add(24 * time.Hour)})
	f := d.preAuthorizedCodeFixture
	f.now = at
	return issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: code, DPoPProof: f.validProofWithNonce(t, nonce), TokenEndpoint: testTokenEndpointURL(t),
	}
}

// challenge returns the nonce a nonce-less Token Request is challenged
// with.
func (d *dpopNonceFixture) challenge(t *testing.T) string {
	t.Helper()
	_, err := d.iss.ExchangePreAuthorizedCode(context.Background(), d.request(t, ""))
	return challengedNonce(t, err)
}

// challengedNonce requires err to be a use_dpop_nonce challenge and
// returns its nonce.
func challengedNonce(t *testing.T, err error) string {
	t.Helper()
	requireIssuerErrorCode(t, err, issuer.ErrorUseDPoPNonce)
	var ierr *issuer.Error
	if !errors.As(err, &ierr) || ierr.Nonce() == "" {
		t.Fatalf("error = %v, want a challenge carrying a nonce", err)
	}
	return ierr.Nonce()
}

// exchange requires a Token Request carrying nonce to succeed now, and
// returns the result's NextDPoPNonce.
func (d *dpopNonceFixture) exchange(t *testing.T, nonce string) string {
	t.Helper()
	result, err := d.iss.ExchangePreAuthorizedCode(context.Background(), d.request(t, nonce))
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode at %v with nonce %q: %v", d.clockNow(), nonce, err)
	}
	return result.NextDPoPNonce
}

// TestExchangePreAuthorizedCode_ConcurrentRequestsShareOneNonce: a
// Wallet uses one nonce until given a new one (RFC 9449 §8.2), so
// concurrent Token Requests carrying it all succeed, and each is handed
// the same current nonce back.
func TestExchangePreAuthorizedCode_ConcurrentRequestsShareOneNonce(t *testing.T) {
	d := newDPoPNonceFixture(t, 5*time.Minute)
	nonce := d.challenge(t)

	const n = 20
	requests := make([]issuer.ExchangePreAuthorizedCodeRequest, n)
	for i := range requests {
		requests[i] = d.request(t, nonce)
	}
	type outcome struct {
		next string
		err  error
	}
	outcomes := make(chan outcome, n)
	var wg sync.WaitGroup
	for _, req := range requests {
		wg.Go(func() {
			result, err := d.iss.ExchangePreAuthorizedCode(context.Background(), req)
			outcomes <- outcome{result.NextDPoPNonce, err}
		})
	}
	wg.Wait()
	close(outcomes)
	for o := range outcomes {
		if o.err != nil {
			t.Fatalf("concurrent ExchangePreAuthorizedCode: %v", o.err)
		}
		if o.next != nonce {
			t.Errorf("NextDPoPNonce = %q, want the current nonce %q", o.next, nonce)
		}
	}
	if d.nonces.issues != 1 {
		t.Errorf("the store was issued %d nonces, want 1", d.nonces.issues)
	}
}

// TestExchangePreAuthorizedCode_RotatesTheNonceAtHalfItsLifetime: the
// Issuer hands out one nonce until half its lifetime has passed, then a
// new one; the previous one is accepted until it expires, and then
// challenged with the current one.
func TestExchangePreAuthorizedCode_RotatesTheNonceAtHalfItsLifetime(t *testing.T) {
	const lifetime = 10 * time.Minute
	d := newDPoPNonceFixture(t, lifetime)
	start := d.clockNow()

	first := d.challenge(t)
	if next := d.exchange(t, first); next != first {
		t.Fatalf("NextDPoPNonce = %q, want the current nonce %q", next, first)
	}

	d.setNow(start.Add(lifetime/2 - time.Second))
	if next := d.exchange(t, first); next != first {
		t.Fatalf("NextDPoPNonce before half the lifetime = %q, want %q still", next, first)
	}

	d.setNow(start.Add(lifetime / 2))
	second := d.exchange(t, first)
	if second == first || second == "" {
		t.Fatalf("NextDPoPNonce at half the lifetime = %q, want a new nonce", second)
	}

	// The previous nonce works until it expires, while the current one
	// is handed out.
	d.setNow(start.Add(lifetime - time.Second))
	if next := d.exchange(t, first); next != second {
		t.Fatalf("NextDPoPNonce = %q, want %q", next, second)
	}
	d.setNow(start.Add(lifetime))
	d.exchange(t, first)

	// Once expired, it's challenged with the current nonce: by now the
	// second has reached half its own lifetime, so that's a third.
	d.setNow(start.Add(lifetime + time.Second))
	_, err := d.iss.ExchangePreAuthorizedCode(context.Background(), d.request(t, first))
	third := challengedNonce(t, err)
	if third == first || third == second {
		t.Errorf("expired nonce challenged with %q, want a new current nonce", third)
	}
	if next := d.exchange(t, second); next != third {
		t.Errorf("NextDPoPNonce = %q, want %q", next, third)
	}
	if next := d.exchange(t, third); next != third {
		t.Errorf("NextDPoPNonce = %q, want %q", next, third)
	}
	if d.nonces.issues != 3 {
		t.Errorf("the store was issued %d nonces, want 3", d.nonces.issues)
	}
}

// TestExchangePreAuthorizedCode_ChallengesExpiredAndUnknownNonces: a
// nonce past its expiry, or one the store doesn't know, is challenged
// with the current nonce, and leaves the pre-authorized code redeemable.
func TestExchangePreAuthorizedCode_ChallengesExpiredAndUnknownNonces(t *testing.T) {
	d := newDPoPNonceFixture(t, time.Minute)
	current := d.challenge(t)
	if err := d.nonces.Issue(context.Background(), issuer.DPoPNonceIssuance{Nonce: "expired", ExpiresAt: d.clockNow().Add(-time.Second)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for _, nonce := range []string{"expired", "never-issued"} {
		req := d.request(t, nonce)
		_, err := d.iss.ExchangePreAuthorizedCode(context.Background(), req)
		if got := challengedNonce(t, err); got != current {
			t.Errorf("%s nonce challenged with %q, want the current nonce %q", nonce, got, current)
		}
		retry := d.request(t, current)
		retry.PreAuthorizedCode = req.PreAuthorizedCode
		if _, err := d.iss.ExchangePreAuthorizedCode(context.Background(), retry); err != nil {
			t.Errorf("retry after the %s nonce's challenge: %v", nonce, err)
		}
	}
}

// TestExchangePreAuthorizedCode_UnavailableNonceStoreIsAServerError: a
// DPoPNonceStore that can't answer fails the request with a plain error,
// a 500 from WriteError, not a use_dpop_nonce challenge that would tell
// the Wallet its proof is stale.
func TestExchangePreAuthorizedCode_UnavailableNonceStoreIsAServerError(t *testing.T) {
	for name, storeErr := range map[string]error{
		"backend down":      errors.New("backend down"),
		"canceled":          context.Canceled,
		"deadline exceeded": fmt.Errorf("lookup: %w", context.DeadlineExceeded),
	} {
		t.Run(name, func(t *testing.T) {
			d := newDPoPNonceFixture(t, time.Minute)
			nonce := d.challenge(t)
			d.nonces.lookupErr = storeErr
			req := d.request(t, nonce)

			_, err := d.iss.ExchangePreAuthorizedCode(context.Background(), req)
			var ierr *issuer.Error
			if err == nil || errors.As(err, &ierr) {
				t.Fatalf("error = %v, want a plain error", err)
			}
			if !errors.Is(err, storeErr) {
				t.Errorf("error = %v, want it to wrap the store's %v", err, storeErr)
			}
			rec := httptest.NewRecorder()
			issuer.WriteError(rec, err)
			if rec.Code != http.StatusInternalServerError || rec.Header().Get("DPoP-Nonce") != "" {
				t.Errorf("WriteError = %d with DPoP-Nonce %q, want 500 without one", rec.Code, rec.Header().Get("DPoP-Nonce"))
			}

			// The code wasn't consumed.
			d.nonces.lookupErr = nil
			retry := d.request(t, nonce)
			retry.PreAuthorizedCode = req.PreAuthorizedCode
			if _, err := d.iss.ExchangePreAuthorizedCode(context.Background(), retry); err != nil {
				t.Errorf("retry once the store answers: %v", err)
			}
		})
	}
}

// TestExchangePreAuthorizedCode_NoDPoPNoncesDeclines: NoDPoPNonces{}
// behaves as a nil DPoPNonces — no nonce is required or handed out —
// and New needs no DPoPNonceLifetime for it.
func TestExchangePreAuthorizedCode_NoDPoPNoncesDeclines(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.DPoPNonces = issuer.NoDPoPNonces{}
	})
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if result.NextDPoPNonce != "" {
		t.Errorf("NextDPoPNonce = %q, want empty", result.NextDPoPNonce)
	}

	// Passed anywhere else as a store, it stores nothing.
	if err := (issuer.NoDPoPNonces{}).Issue(context.Background(), issuer.DPoPNonceIssuance{Nonce: "n"}); err == nil {
		t.Error("NoDPoPNonces.Issue = nil error, want error")
	}
	if _, err := (issuer.NoDPoPNonces{}).Lookup(context.Background(), issuer.DPoPNonceLookup{Nonce: "n"}); err == nil || errors.Is(err, issuer.ErrDPoPNonceUnknown) {
		t.Errorf("NoDPoPNonces.Lookup = %v, want an error other than ErrDPoPNonceUnknown", err)
	}
}
