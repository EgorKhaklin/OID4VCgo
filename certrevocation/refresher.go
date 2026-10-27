package certrevocation

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

// Defaults for a RefresherConfig field left zero, and the fixed bounds
// of Run's schedule.
const (
	// DefaultCRLMaxBytes bounds a fetched CRL's size. An IACA's CRL is
	// a few kilobytes, and a large CA shards its CRLs so each stays well
	// below this; the bound is what a broken or hostile distribution
	// point can make the process buffer.
	DefaultCRLMaxBytes = 8 << 20

	// DefaultCRLFetchTimeout bounds one fetch, every redirect hop
	// included, when RefresherConfig.HTTPClient sets no Timeout.
	DefaultCRLFetchTimeout = 30 * time.Second

	// DefaultCRLMaxInterval is the longest Run waits between passes
	// when every list is current: a revocation the CA publishes is
	// picked up within it, however far off the held list's nextUpdate.
	DefaultCRLMaxInterval = time.Hour

	// MaxCRLRedirects is how many redirects a fetch follows.
	MaxCRLRedirects = 3

	// minRefreshInterval is the shortest Run waits after a pass that
	// succeeded, so a list close to its nextUpdate isn't fetched in a
	// tight loop.
	minRefreshInterval = time.Minute

	// retryBase and retryMax bound Run's backoff after a failed pass:
	// it doubles from retryBase up to retryMax, with jitter.
	retryBase = 30 * time.Second
	retryMax  = 30 * time.Minute
)

// RefresherConfig configures a Refresher.
type RefresherConfig struct {
	// URLs are the CRL distribution points to fetch, http or https:
	// those named by the CRLDistributionPoints of the CA certificates
	// whose issued certificates are checked, configured here by the
	// deployment. They're never discovered from a presented
	// certificate, which would let whoever presents one choose where
	// this process connects. Required, without duplicates.
	URLs []string

	// Issuers are the CA certificates whose CRLs URLs serve. A fetched
	// list replaces the held one only when one of them, by name and
	// signature, issued it. CRLs checks the signature itself at every
	// check; checking it on fetch too keeps a forged or corrupted
	// response from evicting a good list, and makes the rollback checks
	// (see Refresh) compare signed values rather than whatever a plain
	// http response carried. Required.
	Issuers []*x509.Certificate

	// HTTPClient makes the fetches. Nil means a client built with
	// fapihttp.NewClient (fapihttp.RecommendedTransportConfig), which
	// dials only public addresses: loopback, private, link-local,
	// unspecified, multicast and the other special-purpose ranges are
	// refused when the connection is dialled, after resolving the
	// host, so a name resolving to an internal address is refused too.
	// A client given here is used as given, and its transport decides
	// what it can reach: build it with fapihttp.NewClient too. Either
	// way its CheckRedirect is replaced (see Refresh), and a client
	// without a Timeout gets DefaultCRLFetchTimeout.
	HTTPClient *http.Client

	// AllowLoopback lets the default client dial loopback addresses,
	// for local development and tests. It can't be combined with
	// HTTPClient, whose own transport decides that.
	AllowLoopback bool

	// MaxBytes bounds a CRL's size; zero means DefaultCRLMaxBytes.
	MaxBytes int64

	// MaxInterval is the longest Run waits between passes; zero means
	// DefaultCRLMaxInterval.
	MaxInterval time.Duration

	// OnError, if set, is called by Run for every URL a pass failed
	// for, with the URL (its password redacted) and the error. Run has
	// no other way to report one: the library logs nothing.
	OnError func(url string, err error)

	// Clock is the current time; nil means time.Now. Tests set it.
	Clock func() time.Time
}

// Refresher fetches CRLs from configured distribution points and holds
// the last good list from each in memory, for CRLs to check against:
// CRLs{Lists: r.Lists}, which Checker returns. Lists never fetches.
//
// NewRefresher starts nothing. Run keeps the lists current in a loop
// the caller starts in its own goroutine (go r.Run(ctx)); Refresh is
// one pass, for a caller that schedules refreshes itself. Fetch once
// with Refresh before serving, or CRLs fails closed with
// ErrNoCurrentCRL until Run's first pass completes. On a phone, let
// the operating system's background scheduler drive refreshes and
// hand the lists to the mobile library's SetCRLs (mobile/ABI.md)
// instead: an app's own goroutine doesn't run while it's suspended.
//
// A Refresher is safe for concurrent use.
type Refresher struct {
	urls        []string
	issuers     []*x509.Certificate
	client      http.Client
	maxBytes    int64
	maxInterval time.Duration
	onError     func(string, error)
	now         func() time.Time

	// wait sleeps for d, returning false when ctx ends first, and
	// jitter returns a random duration in [0, n); tests replace them.
	wait   func(ctx context.Context, d time.Duration) bool
	jitter func(n time.Duration) time.Duration

	mu   sync.RWMutex
	held map[string]heldCRL
}

// heldCRL is the last good list from one URL, and when it was fetched.
type heldCRL struct {
	list      *x509.RevocationList
	fetchedAt time.Time
}

// NewRefresher validates cfg and returns a Refresher holding no lists
// yet.
func NewRefresher(cfg RefresherConfig) (*Refresher, error) {
	if len(cfg.URLs) == 0 {
		return nil, errors.New("certrevocation: RefresherConfig.URLs is required")
	}
	for i, raw := range cfg.URLs {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("certrevocation: RefresherConfig.URLs[%d] isn't an http or https URL", i)
		}
		if slices.Contains(cfg.URLs[:i], raw) {
			return nil, fmt.Errorf("certrevocation: RefresherConfig.URLs[%d] repeats %s", i, u.Redacted())
		}
	}
	if len(cfg.Issuers) == 0 || slices.Contains(cfg.Issuers, nil) {
		return nil, errors.New("certrevocation: RefresherConfig.Issuers is required, without nil certificates")
	}
	if cfg.MaxBytes < 0 || cfg.MaxInterval < 0 {
		return nil, errors.New("certrevocation: RefresherConfig.MaxBytes and MaxInterval can't be negative")
	}
	client, err := refresherClient(cfg)
	if err != nil {
		return nil, err
	}
	r := &Refresher{
		urls:        slices.Clone(cfg.URLs),
		issuers:     slices.Clone(cfg.Issuers),
		client:      client,
		maxBytes:    cmp.Or(cfg.MaxBytes, DefaultCRLMaxBytes),
		maxInterval: cmp.Or(cfg.MaxInterval, DefaultCRLMaxInterval),
		onError:     cfg.OnError,
		now:         cfg.Clock,
		wait:        sleep,
		jitter:      func(n time.Duration) time.Duration { return rand.N(n) }, //nolint:gosec // retry jitter, not a secret
		held:        make(map[string]heldCRL, len(cfg.URLs)),
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r, nil
}

// refresherClient is the client cfg asks for, with the redirect policy
// and a timeout applied.
func refresherClient(cfg RefresherConfig) (http.Client, error) {
	var client http.Client
	switch {
	case cfg.HTTPClient != nil && cfg.AllowLoopback:
		return client, errors.New("certrevocation: RefresherConfig.AllowLoopback applies only to the default client, not to HTTPClient")
	case cfg.HTTPClient != nil:
		client = *cfg.HTTPClient
	default:
		tc := fapihttp.RecommendedTransportConfig()
		tc.AllowLoopbackHosts = cfg.AllowLoopback
		built, err := fapihttp.NewClient(tc)
		if err != nil {
			return client, fmt.Errorf("certrevocation: build the HTTP client: %w", err)
		}
		client = *built
	}
	if client.Timeout <= 0 {
		client.Timeout = DefaultCRLFetchTimeout
	}
	client.CheckRedirect = checkCRLRedirect
	return client, nil
}

// checkCRLRedirect follows at most MaxCRLRedirects redirects, each on
// the original host and port, over the same scheme or from http up to
// https. A distribution point moving its file behind a redirect stays
// reachable, but the configured URL can't send the fetch to another
// host: the URL list is the whole set of places this process fetches
// from.
func checkCRLRedirect(next *http.Request, via []*http.Request) error {
	first := via[0].URL
	switch {
	case len(via) > MaxCRLRedirects:
		return fmt.Errorf("more than %d redirects", MaxCRLRedirects)
	case next.URL.Host != first.Host:
		return fmt.Errorf("a redirect to another host, %s", next.URL.Redacted())
	case next.URL.Scheme != first.Scheme && next.URL.Scheme != "https":
		return fmt.Errorf("a redirect from %s to %s", first.Scheme, next.URL.Scheme)
	}
	return nil
}

// Lists returns the list held from each URL that has been fetched, in
// URLs order, for CRLs.Lists. It never fetches and never fails. A list
// past its nextUpdate is returned too, until a newer one replaces it:
// CRLs doesn't use it, so a certificate its CA issued is refused with
// ErrNoCurrentCRL, as it would be with no list at all.
func (r *Refresher) Lists(context.Context) ([]*x509.RevocationList, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	lists := make([]*x509.RevocationList, 0, len(r.held))
	for _, u := range r.urls {
		if h, ok := r.held[u]; ok {
			lists = append(lists, h.list)
		}
	}
	return lists, nil
}

// Checker returns CRLs checking against r's held lists, with r's
// Issuers as its own, for a pinned certificate one of them issued.
func (r *Refresher) Checker() CRLs {
	return CRLs{Lists: r.Lists, Issuers: slices.Clone(r.issuers)}
}

// Refresh fetches every URL once, in turn, and returns the failures
// joined, each naming its URL; it never includes a response body.
//
// A fetch is a GET that must answer 2xx with a CRL no larger than
// MaxBytes, in DER or as a PEM "X509 CRL" block, whatever its Content-
// Type. Redirects are followed only on the same host (see
// RefresherConfig.HTTPClient). The list replaces the one held from
// that URL only when it is complete and direct (as CRLs requires: not
// a delta CRL, no issuing distribution point, no critical extension it
// doesn't process), has a nextUpdate, is current now (within
// CRLClockSkew), was issued by one of Issuers, names the same issuer as
// the held list, and isn't older than it: its thisUpdate isn't before
// the held list's, and when both carry a CRL number, its number isn't
// lower. That last check stops a replayed old list, one still inside
// its validity, from bringing back a certificate revoked since. Any
// failure keeps the held list, and a URL whose held list has passed
// its nextUpdate is a failure too, until a current one is fetched.
func (r *Refresher) Refresh(ctx context.Context) error {
	var errs []error
	r.refresh(ctx, func(_ string, err error) { errs = append(errs, err) })
	return errors.Join(errs...)
}

// refresh is Refresh, reporting each URL's failure to fail.
func (r *Refresher) refresh(ctx context.Context, fail func(url string, err error)) {
	for _, u := range r.urls {
		if err := r.refreshOne(ctx, u); err != nil {
			fail(redacted(u), fmt.Errorf("certrevocation: CRL %s: %w", redacted(u), err))
		}
	}
}

// refreshOne fetches u and keeps the list if it's acceptable.
func (r *Refresher) refreshOne(ctx context.Context, u string) error {
	fetched, fetchErr := r.fetch(ctx, u)
	r.mu.Lock()
	defer r.mu.Unlock()
	held, holding := r.held[u]
	now := r.now()
	if fetchErr == nil {
		if fetchErr = r.acceptable(fetched, held.list, now); fetchErr == nil {
			r.held[u] = heldCRL{list: fetched, fetchedAt: now}
			return nil
		}
	}
	if holding && !now.Before(held.list.NextUpdate) {
		return fmt.Errorf("%w; the held list expired at %s", fetchErr, held.list.NextUpdate.UTC().Format(time.RFC3339))
	}
	return fetchErr
}

// acceptable refuses list in place of held (nil when nothing is held
// yet) at now.
func (r *Refresher) acceptable(list, held *x509.RevocationList, now time.Time) error {
	switch {
	case !completeAndDirect(list):
		return errors.New("a delta or scoped CRL (issuing distribution point), not a complete one")
	case !criticalUnderstood(list):
		return errors.New("the CRL carries a critical extension this package doesn't process")
	case list.NextUpdate.IsZero():
		return errors.New("the CRL has no nextUpdate")
	case notYetValid(list, now):
		return fmt.Errorf("the CRL isn't valid until %s", list.ThisUpdate.UTC().Format(time.RFC3339))
	case !now.Before(list.NextUpdate):
		return fmt.Errorf("the CRL expired at %s", list.NextUpdate.UTC().Format(time.RFC3339))
	case !r.signedByIssuer(list):
		return errors.New("the CRL isn't signed by any of the configured issuers")
	case held == nil:
		return nil
	case !bytes.Equal(list.RawIssuer, held.RawIssuer):
		return errors.New("the CRL names another issuer than the held one")
	case list.ThisUpdate.Before(held.ThisUpdate):
		return fmt.Errorf("the CRL's thisUpdate %s is before the held one's", list.ThisUpdate.UTC().Format(time.RFC3339))
	case list.Number != nil && held.Number != nil && list.Number.Cmp(held.Number) < 0:
		return fmt.Errorf("the CRL number %s is lower than the held one's, %s", list.Number, held.Number)
	}
	return nil
}

// signedByIssuer reports whether one of r's issuers, by name and
// signature, issued list.
func (r *Refresher) signedByIssuer(list *x509.RevocationList) bool {
	for _, issuer := range r.issuers {
		if bytes.Equal(list.RawIssuer, issuer.RawSubject) && list.CheckSignatureFrom(issuer) == nil {
			return true
		}
	}
	return false
}

// fetch GETs u and parses the CRL it answers with.
func (r *Refresher) fetch(ctx context.Context, u string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.New("can't build the request")
	}
	req.Header.Set("Accept", "application/pkix-crl")
	resp, err := r.client.Do(req)
	if err != nil {
		// url.Error repeats the URL, which the caller names already.
		if ue := (*url.Error)(nil); errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, r.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the response: %w", err)
	}
	if int64(len(body)) > r.maxBytes {
		return nil, fmt.Errorf("the response exceeds %d bytes", r.maxBytes)
	}
	return parseCRL(body)
}

// parseCRL parses a DER CRL, or one PEM "X509 CRL" block.
func parseCRL(body []byte) (*x509.RevocationList, error) {
	der := body
	if trimmed := bytes.TrimSpace(body); bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, _ := pem.Decode(trimmed)
		if block == nil || block.Type != "X509 CRL" {
			return nil, errors.New("the response is PEM, but not an X509 CRL block")
		}
		der = block.Bytes
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse the CRL: %w", err)
	}
	return list, nil
}

// redacted is u with any password redacted, for an error.
func redacted(u string) string {
	if parsed, err := url.Parse(u); err == nil {
		return parsed.Redacted()
	}
	return u
}

// Run keeps the held lists current until ctx ends: a pass of Refresh,
// then a wait, then another. After a pass that succeeded for every
// URL, it waits until the first held list is halfway from when it was
// fetched to its nextUpdate, but no longer than MaxInterval and no
// less than a minute. Since each fetch moves that point on, the waits
// shorten as a nextUpdate nears without the CA having published a
// newer list, and never run past it unless it's under a minute away.
// After a pass that failed for any URL, it retries after a backoff
// that starts at 30 seconds and doubles up to 30 minutes, with jitter,
// or sooner if the schedule above says so. OnError hears of each
// failure. Run returns when ctx ends, and starts no goroutine of its
// own: run it with go r.Run(ctx).
func (r *Refresher) Run(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		failed := false
		r.refresh(ctx, func(u string, err error) {
			failed = true
			if r.onError != nil && ctx.Err() == nil {
				r.onError(u, err)
			}
		})
		delay := r.nextDelay()
		if failed {
			failures++
			delay = min(delay, retryDelay(failures, r.jitter))
		} else {
			failures = 0
		}
		if !r.wait(ctx, delay) {
			return
		}
	}
}

// nextDelay is how long Run waits after a pass, by refreshDelay.
func (r *Refresher) nextDelay() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]scheduleEntry, len(r.urls))
	for i, u := range r.urls {
		if h, ok := r.held[u]; ok {
			entries[i] = scheduleEntry{held: true, fetchedAt: h.fetchedAt, nextUpdate: h.list.NextUpdate}
		}
	}
	return refreshDelay(r.now(), entries, r.maxInterval)
}

// scheduleEntry is what refreshDelay knows of one URL: whether a list
// is held, when it was fetched and its nextUpdate.
type scheduleEntry struct {
	held                  bool
	fetchedAt, nextUpdate time.Time
}

// refreshDelay is how long to wait at now before the next pass: until
// the earliest point halfway from an entry's fetchedAt to its
// nextUpdate, at once for an entry with no list held, capped at
// maxInterval and at least minRefreshInterval.
func refreshDelay(now time.Time, entries []scheduleEntry, maxInterval time.Duration) time.Duration {
	delay := maxInterval
	for _, e := range entries {
		due := now
		if e.held {
			due = e.fetchedAt.Add(e.nextUpdate.Sub(e.fetchedAt) / 2)
		}
		delay = min(delay, due.Sub(now))
	}
	return max(delay, minRefreshInterval)
}

// retryDelay is the backoff after the given number of consecutive
// failed passes: retryBase doubled per failure past the first, capped
// at retryMax, of which a random half is taken off.
func retryDelay(failures int, jitter func(time.Duration) time.Duration) time.Duration {
	delay := retryMax
	if shift := failures - 1; shift < 16 {
		delay = min(retryBase<<shift, retryMax)
	}
	half := delay / 2
	return half + jitter(half)
}

// sleep waits for d, returning false when ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
