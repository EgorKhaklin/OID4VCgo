package certrevocation_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// crlServer serves a response per path that a test can change.
type crlServer struct {
	*httptest.Server
	mu        sync.Mutex
	responses map[string]crlResponse
	hits      int
}

type crlResponse struct {
	status   int
	body     []byte
	location string
}

func newCRLServer(t *testing.T) *crlServer {
	t.Helper()
	s := &crlServer{responses: map[string]crlResponse{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.mu.Lock()
		resp, ok := s.responses[req.URL.Path]
		s.hits++
		s.mu.Unlock()
		switch {
		case !ok:
			http.NotFound(w, req)
		case resp.location != "":
			http.Redirect(w, req, resp.location, http.StatusFound)
		default:
			w.Header().Set("Content-Type", "application/pkix-crl")
			w.WriteHeader(resp.status)
			_, _ = w.Write(resp.body)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// serve has path answer with status and body.
func (s *crlServer) serve(path string, status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responses[path] = crlResponse{status: status, body: body}
}

// serveCRL has path answer with list in DER.
func (s *crlServer) serveCRL(path string, list *x509.RevocationList) {
	s.serve(path, http.StatusOK, list.Raw)
}

// redirect has path redirect to location.
func (s *crlServer) redirect(path, location string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responses[path] = crlResponse{location: location}
}

func (s *crlServer) hitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// newRefresher is a Refresher for urls whose lists issuers sign, with
// loopback allowed, failing t on a configuration error.
func newRefresher(t *testing.T, cfg certrevocation.RefresherConfig) *certrevocation.Refresher {
	t.Helper()
	cfg.AllowLoopback = cfg.HTTPClient == nil
	r, err := certrevocation.NewRefresher(cfg)
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	return r
}

// heldList is the one list r holds.
func heldList(t *testing.T, r *certrevocation.Refresher) *x509.RevocationList {
	t.Helper()
	lists, err := r.Lists(context.Background())
	if err != nil || len(lists) != 1 {
		t.Fatalf("Lists = %d lists, %v; want one", len(lists), err)
	}
	return lists[0]
}

// numbered is a CRL from issuer/key with the given number and
// thisUpdate (relative to now), current for two hours after it.
func numbered(t *testing.T, issuer *x509.Certificate, key crypto.Signer, number int64, thisUpdate time.Duration, revoked ...*big.Int) *x509.RevocationList {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: time.Now().Add(thisUpdate), NextUpdate: time.Now().Add(thisUpdate + 2*time.Hour)}
	for _, serial := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: time.Now().Add(-time.Minute)})
	}
	return testcert.CRLFromTemplate(t, tmpl, issuer, key)
}

// withoutNextUpdate is list re-signed by key with its nextUpdate
// removed, which x509.CreateRevocationList can't produce.
func withoutNextUpdate(t *testing.T, list *x509.RevocationList, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	var cl pkix.CertificateList
	if _, err := asn1.Unmarshal(list.Raw, &cl); err != nil {
		t.Fatal(err)
	}
	cl.TBSCertList.Raw = nil
	cl.TBSCertList.NextUpdate = time.Time{}
	tbs, err := asn1.Marshal(cl.TBSCertList)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, cl.SignatureAlgorithm, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNewRefresher_Validates(t *testing.T) {
	p := newPKI(t)
	issuers := []*x509.Certificate{p.inter}
	tests := map[string]certrevocation.RefresherConfig{
		"no URLs":         {Issuers: issuers},
		"not http":        {URLs: []string{"ftp://crl.example/ca.crl"}, Issuers: issuers},
		"no host":         {URLs: []string{"http:///ca.crl"}, Issuers: issuers},
		"repeated URL":    {URLs: []string{"http://crl.example/ca.crl", "http://crl.example/ca.crl"}, Issuers: issuers},
		"no issuers":      {URLs: []string{"http://crl.example/ca.crl"}},
		"nil issuer":      {URLs: []string{"http://crl.example/ca.crl"}, Issuers: []*x509.Certificate{nil}},
		"negative size":   {URLs: []string{"http://crl.example/ca.crl"}, Issuers: issuers, MaxBytes: -1},
		"loopback+client": {URLs: []string{"http://crl.example/ca.crl"}, Issuers: issuers, HTTPClient: &http.Client{}, AllowLoopback: true},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := certrevocation.NewRefresher(cfg); err == nil {
				t.Error("NewRefresher: nil error")
			}
		})
	}
	if _, err := certrevocation.NewRefresher(certrevocation.RefresherConfig{URLs: []string{"https://crl.example/ca.crl"}, Issuers: issuers}); err != nil {
		t.Errorf("NewRefresher, valid: %v", err)
	}
}

func TestRefresher_FetchesDERAndPEM(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}})
	if lists, _ := r.Lists(context.Background()); len(lists) != 0 {
		t.Fatalf("Lists before any fetch = %d lists", len(lists))
	}

	der := numbered(t, p.inter, p.interKey, 1, -time.Hour)
	srv.serveCRL("/ca.crl", der)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh, DER: %v", err)
	}
	if got := heldList(t, r); !bytes.Equal(got.Raw, der.Raw) {
		t.Error("DER list not held")
	}

	pemList := numbered(t, p.inter, p.interKey, 2, -time.Hour, p.leaf.SerialNumber)
	srv.serve("/ca.crl", http.StatusOK, append([]byte("\n"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: pemList.Raw})...))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh, PEM: %v", err)
	}
	if got := heldList(t, r); !bytes.Equal(got.Raw, pemList.Raw) {
		t.Error("PEM list not held")
	}
	// The same list again is accepted: it isn't older.
	if err := r.Refresh(context.Background()); err != nil {
		t.Errorf("Refresh, same list: %v", err)
	}
}

// TestRefresher_KeepsHeldList checks that every kind of bad fetch is
// an error naming the URL, and leaves the held list in place.
func TestRefresher_KeepsHeldList(t *testing.T) {
	p := newPKI(t)
	const maxBytes = 64 << 10
	good := numbered(t, p.inter, p.interKey, 5, -time.Hour)
	tests := map[string]struct {
		status int
		body   []byte
		want   string
	}{
		"server error":   {http.StatusInternalServerError, good.Raw, "HTTP 500"},
		"not found":      {http.StatusNotFound, nil, "HTTP 404"},
		"oversized":      {http.StatusOK, make([]byte, maxBytes+1), "exceeds"},
		"unparseable":    {http.StatusOK, []byte("SECRET-BODY-MARKER"), "parse the CRL"},
		"PEM, not a CRL": {http.StatusOK, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.leaf.Raw}), "not an X509 CRL"},
		"swapped issuer": {http.StatusOK, testcert.CRL(t, p.otherCA, p.otherKey).Raw, "another issuer"},
		"forged signer":  {http.StatusOK, numbered(t, p.fakeInter, p.fakeKey, 6, 0).Raw, "configured issuers"},
		"older thisUpdate": {http.StatusOK, numbered(t, p.inter, p.interKey, 6, -90*time.Minute).Raw,
			"before the held one's"},
		"lower CRL number": {http.StatusOK, numbered(t, p.inter, p.interKey, 4, 0).Raw, "lower than the held one's"},
		"no nextUpdate":    {http.StatusOK, withoutNextUpdate(t, numbered(t, p.inter, p.interKey, 6, 0), p.interKey), "no nextUpdate"},
		"expired": {http.StatusOK, testcert.CRLFromTemplate(t, &x509.RevocationList{
			Number: big.NewInt(6), ThisUpdate: time.Now().Add(-30 * time.Minute), NextUpdate: time.Now().Add(-time.Minute),
		}, p.inter, p.interKey).Raw, "expired at"},
		"not yet valid": {http.StatusOK, numbered(t, p.inter, p.interKey, 6, time.Hour).Raw, "isn't valid until"},
		"delta CRL": {http.StatusOK, testcert.CRLFromTemplate(t, withExtension(t, asn1.ObjectIdentifier{2, 5, 29, 27}, 1), p.inter, p.interKey).Raw,
			"not a complete one"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := newCRLServer(t)
			// The other CA is configured too: its list, signed and
			// current, is refused only for not being this URL's issuer.
			issuers := []*x509.Certificate{p.inter, p.otherCA}
			r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: issuers, MaxBytes: maxBytes})
			srv.serveCRL("/ca.crl", good)
			if err := r.Refresh(context.Background()); err != nil {
				t.Fatalf("Refresh, good list: %v", err)
			}
			srv.serve("/ca.crl", tc.status, tc.body)
			err := r.Refresh(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Refresh = %v, want an error containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), srv.URL+"/ca.crl") || strings.Contains(err.Error(), "SECRET-BODY-MARKER") {
				t.Errorf("Refresh = %v: should name the URL and never quote the body", err)
			}
			if got := heldList(t, r); !bytes.Equal(got.Raw, good.Raw) {
				t.Error("the held list was replaced")
			}
		})
	}
}

func TestRefresher_UnknownIssuerWithoutHeldList(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", testcert.CRL(t, p.otherCA, p.otherKey))
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}})
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh: nil error for a list from an unconfigured issuer")
	}
	if lists, _ := r.Lists(context.Background()); len(lists) != 0 {
		t.Errorf("Lists = %d lists, want none", len(lists))
	}
}

func TestRefresher_ReportsExpiredHeldList(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", numbered(t, p.inter, p.interKey, 1, -time.Hour))
	now := time.Now()
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}, Clock: func() time.Time { return now }})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.serve("/ca.crl", http.StatusServiceUnavailable, nil)
	now = now.Add(3 * time.Hour)
	if err := r.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "held list expired") {
		t.Errorf("Refresh = %v, want it to report the held list expired", err)
	}
}

func TestRefresher_Redirects(t *testing.T) {
	p := newPKI(t)
	list := numbered(t, p.inter, p.interKey, 1, -time.Hour)
	srv := newCRLServer(t)
	other := newCRLServer(t)
	srv.serveCRL("/moved.crl", list)
	other.serveCRL("/ca.crl", list)
	srv.redirect("/same-host.crl", "/moved.crl")
	srv.redirect("/other-host.crl", other.URL+"/ca.crl")
	srv.redirect("/loop.crl", "/loop.crl")

	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/same-host.crl"}, Issuers: []*x509.Certificate{p.inter}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Errorf("same-host redirect: %v", err)
	}
	for path, want := range map[string]string{"/other-host.crl": "another host", "/loop.crl": "redirects"} {
		r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + path}, Issuers: []*x509.Certificate{p.inter}})
		if err := r.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: Refresh = %v, want an error containing %q", path, err, want)
		}
	}
	if other.hitCount() != 0 {
		t.Error("the other host was fetched from")
	}
}

func TestRefresher_DefaultClientRefusesLoopback(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", numbered(t, p.inter, p.interKey, 1, -time.Hour))
	u := strings.Replace(srv.URL, "http://", "http://user:hunter2@", 1) + "/ca.crl"
	r, err := certrevocation.NewRefresher(certrevocation.RefresherConfig{URLs: []string{u}, Issuers: []*x509.Certificate{p.inter}})
	if err != nil {
		t.Fatal(err)
	}
	err = r.Refresh(context.Background())
	if !errors.Is(err, fapihttp.ErrSSRFBlocked) {
		t.Errorf("Refresh = %v, want fapihttp.ErrSSRFBlocked", err)
	}
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Errorf("Refresh = %v: should redact the URL's password", err)
	}
	if srv.hitCount() != 0 {
		t.Error("the loopback server was reached")
	}
}

func TestRefresher_GivenHTTPClient(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", numbered(t, p.inter, p.interKey, 1, -time.Hour))
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}, HTTPClient: srv.Client()})
	if err := r.Refresh(context.Background()); err != nil {
		t.Errorf("Refresh: %v", err)
	}
}

func TestRefresher_ConcurrentLists(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", numbered(t, p.inter, p.interKey, 1, -time.Hour))
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}})
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	checker := r.Checker()
	check := certrevocation.Check{Chain: []*x509.Certificate{p.leaf, p.inter}}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				if err := checker.CheckRevocation(context.Background(), check); err != nil && !errors.Is(err, certrevocation.ErrRevoked) {
					t.Errorf("CheckRevocation: %v", err)
					return
				}
			}
		})
	}
	var newer []*x509.RevocationList
	for i := range 10 {
		newer = append(newer, numbered(t, p.inter, p.interKey, int64(i+2), -time.Hour, p.leaf.SerialNumber))
	}
	wg.Go(func() {
		for _, list := range newer {
			srv.serveCRL("/ca.crl", list)
			_ = r.Refresh(context.Background())
		}
	})
	wg.Wait()
}

// TestRefresher_Run checks Run's loop with its waits recorded instead
// of slept: the schedule after a good pass, backoff after failures,
// and OnError.
func TestRefresher_Run(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	now := time.Now().Truncate(time.Second) // a CRL's times have whole seconds
	srv.serveCRL("/ca.crl", testcert.CRLFromTemplate(t, &x509.RevocationList{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, p.inter, p.interKey))
	var failed []string
	r := newRefresher(t, certrevocation.RefresherConfig{
		URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter},
		Clock:   func() time.Time { return now },
		OnError: func(u string, err error) { failed = append(failed, u) },
	})
	var waits []time.Duration
	r.SetScheduleForTest(func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		srv.serve("/ca.crl", http.StatusBadGateway, nil) // every later pass fails
		return len(waits) < 3
	}, func(time.Duration) time.Duration { return 0 })
	r.Run(context.Background())

	want := []time.Duration{30 * time.Minute, 15 * time.Second, 30 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("waits = %v, want %v", waits, want)
			break
		}
	}
	if len(failed) != 2 || failed[0] != srv.URL+"/ca.crl" {
		t.Errorf("OnError heard %v, want the URL twice", failed)
	}
	if srv.hitCount() != 3 {
		t.Errorf("%d fetches, want 3", srv.hitCount())
	}
}

func TestRefresher_RunStopsWithContext(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/ca.crl", numbered(t, p.inter, p.interKey, 1, -time.Hour))
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	deadline := time.After(10 * time.Second)
	for srv.hitCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run made no fetch")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Run didn't return after its context ended")
	}
}

// TestRefresher_RevokesThroughResolver runs a Refresher's lists through
// the verifier's issuer trust: a document signer accepted under the
// IACA's first CRL is refused once a refresh picks up one revoking it.
func TestRefresher_RevokesThroughResolver(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	srv.serveCRL("/root.crl", numbered(t, p.root, p.rootKey, 1, -time.Hour))
	srv.serveCRL("/inter.crl", numbered(t, p.inter, p.interKey, 1, -time.Hour))
	r := newRefresher(t, certrevocation.RefresherConfig{
		URLs:    []string{srv.URL + "/inter.crl", srv.URL + "/root.crl"},
		Issuers: []*x509.Certificate{p.inter, p.root},
	})
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	resolver := verifier.X5ChainIssuerKeyResolver{
		Roots:      roots,
		LeafPolicy: func(*x509.Certificate, [][]*x509.Certificate) error { return nil },
		Revocation: r.Checker(),
	}
	x5chain := [][]byte{p.leaf.Raw, p.inter.Raw}
	resolve := func() error {
		_, err := resolver.ResolveMdocIssuerChains(context.Background(), x5chain, "org.iso.18013.5.1.mDL")
		return err
	}

	if err := resolve(); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
		t.Fatalf("before any refresh: %v, want ErrNoCurrentCRL", err)
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := resolve(); err != nil {
		t.Fatalf("after the first refresh: %v", err)
	}
	srv.serveCRL("/inter.crl", numbered(t, p.inter, p.interKey, 2, -time.Hour, p.leaf.SerialNumber))
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := resolve(); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("after the revoking refresh: %v, want ErrRevoked", err)
	}
}
