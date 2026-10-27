package walletflow

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestNew_DefaultHTTPRefusesPrivateAddresses: without Dependencies.HTTP,
// the wallet's own requests — token, credential, response_uri — can't
// be pointed at its own network: the default client won't dial a
// private or loopback address outside Development.
func TestNew_DefaultHTTPRefusesPrivateAddresses(t *testing.T) {
	w, err := New(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb"}, Dependencies{
		Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://10.0.0.1/token", "https://127.0.0.1/token", "https://169.254.169.254/latest"} {
		resp, err := w.deps.HTTP.Get(target)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("GET %s succeeded, want refused", target)
		}
	}
}

// countingTransport is a RoundTripper counting the requests it sends.
type countingTransport struct {
	base http.RoundTripper
	sent atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.sent.Add(1)
	return c.base.RoundTrip(r)
}

// TestNew_CallersHTTPGetsTimeout: a caller's HTTP client without a
// Timeout is used through a copy with httpTimeout, its Transport and
// CheckRedirect kept, so a server that never answers doesn't hold a
// request until its context ends; the caller's own client is left as it
// was, and one with a Timeout of its own is used as it is.
func TestNew_CallersHTTPGetsTimeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	errRedirect := errors.New("no redirects")
	transport := &countingTransport{base: http.DefaultTransport}
	given := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
	deps := Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore(), HTTP: given}
	w, err := New(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", Development: true}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if given.Timeout != 0 {
		t.Errorf("the caller's client was changed: Timeout %v", given.Timeout)
	}
	if w.deps.HTTP.Timeout != httpTimeout || w.deps.HTTP.Transport != transport || w.deps.HTTP.CheckRedirect == nil || w.deps.HTTP.CheckRedirect(nil, nil) != errRedirect {
		t.Errorf("client = %+v, want the caller's with Timeout %v", w.deps.HTTP, httpTimeout)
	}

	start := time.Now()
	resp, err := w.deps.HTTP.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a server that never answers answered")
	}
	if elapsed := time.Since(start); elapsed > httpTimeout+5*time.Second {
		t.Errorf("gave up after %v, want about %v", elapsed, httpTimeout)
	}
	if transport.sent.Load() != 1 {
		t.Errorf("caller's transport sent %d requests, want 1", transport.sent.Load())
	}

	own := &http.Client{Timeout: time.Minute}
	w, err = New(Config{ClientID: "wallet", RedirectURI: "com.example.wallet:/cb", Development: true}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore(), HTTP: own})
	if err != nil {
		t.Fatal(err)
	}
	if w.deps.HTTP != own {
		t.Error("a client with its own Timeout was replaced")
	}
}

// TestCleanText: an authorization callback's error text drops control
// characters and is cut short.
func TestCleanText(t *testing.T) {
	got := cleanText("denied\r\nINFO forged" + strings.Repeat("x", 1000))
	if strings.ContainsAny(got, "\r\n") || len([]rune(got)) != maxErrorTextRunes+1 || !strings.HasSuffix(got, "…") {
		t.Errorf("cleanText = %q", got)
	}
}
