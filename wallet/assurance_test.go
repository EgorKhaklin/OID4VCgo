package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/idfoundry/fapigo/fapihttp"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

func TestNewRejectsInvalidAssurance(t *testing.T) {
	for _, level := range []wallet.AssuranceLevel{0, 99} {
		cfg := validConfig()
		cfg.Assurance = level
		if _, err := wallet.New(cfg, validDependencies()); err == nil {
			t.Errorf("New(Assurance=%d) = nil error, want error", level)
		}
	}
}

func TestNewProductionRejectsAllowLoopbackHTTP(t *testing.T) {
	cfg := validConfig() // sets Fetch.AllowLoopbackHTTP
	cfg.Assurance = wallet.AssuranceProduction
	_, err := wallet.New(cfg, validDependencies())
	if err == nil || !strings.Contains(err.Error(), "allow_loopback_http") {
		t.Fatalf("New(AssuranceProduction, AllowLoopbackHTTP) error = %v, want an allow_loopback_http rejection", err)
	}
}

func TestNewProductionRejectsAllowLoopbackHosts(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP, cfg.Fetch.AllowLoopbackHosts = false, true
	_, err := wallet.New(cfg, validDependencies())
	if err == nil || !strings.Contains(err.Error(), "allow_loopback_hosts") {
		t.Fatalf("New(AssuranceProduction, AllowLoopbackHosts) error = %v, want an allow_loopback_hosts rejection", err)
	}
}

// AllowedLoopbackHosts is one of fapihttp's loopback exceptions: the
// transport New builds would dial loopback for a listed host.
func TestNewProductionRejectsAllowedLoopbackHosts(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	cfg.Fetch.AllowedLoopbackHosts = []string{"issuer-sidecar.internal"}
	_, err := wallet.New(cfg, productionDependencies())
	if err == nil || !strings.Contains(err.Error(), "allowed_loopback_hosts") {
		t.Fatalf("New(AssuranceProduction, AllowedLoopbackHosts) error = %v, want an allowed_loopback_hosts rejection", err)
	}
}

func TestNewProductionAcceptsHardenedFetch(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	// An explicit private-host allow-list is a deployment choice, not a
	// development switch, so it stays permitted.
	cfg.Fetch.AllowedPrivateHosts = []string{"issuer.internal"}
	if _, err := wallet.New(cfg, productionDependencies()); err != nil {
		t.Fatalf("New(AssuranceProduction): %v", err)
	}
}

// Under production, DPoP jti values come from crypto/rand.Reader: nil
// means it, and any other source is refused.
func TestNewProductionRequiresCryptoRandom(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	for name, tc := range map[string]struct {
		random io.Reader
		ok     bool
	}{
		"crypto/rand.Reader": {rand.Reader, true},
		"nil":                {nil, true},
		"another reader":     {strings.NewReader(strings.Repeat("x", 1024)), false},
	} {
		deps := productionDependencies()
		deps.Random = tc.random
		w, err := wallet.New(cfg, deps)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
			continue
		}
		if err == nil {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if _, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token", "", ""); err != nil {
				t.Errorf("%s: GenerateDPoPProof: %v", name, err)
			}
		}
	}
}

// productionDependencies is validDependencies with no HTTP client, so
// New builds fapihttp's hardened one, as production requires.
func productionDependencies() wallet.Dependencies {
	deps := validDependencies()
	deps.HTTP = nil
	return deps
}

// Under production, the HTTP client must be fapihttp.NewClient's, its
// transport intact, with no loopback exception: only that transport
// refuses private addresses when it dials.
func TestNewProductionChecksHTTPClient(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	hardened, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	loopbackCfg := fapihttp.RecommendedTransportConfig()
	loopbackCfg.AllowLoopbackHosts = true
	loopback, err := fapihttp.NewClient(loopbackCfg)
	if err != nil {
		t.Fatal(err)
	}
	copied := *hardened
	copied.Timeout = time.Second
	for name, tc := range map[string]struct {
		client fapihttp.HTTPClient
		ok     bool
	}{
		"none: New builds one":       {nil, true},
		"NewClient's":                {hardened, true},
		"a copy of NewClient's":      {&copied, true},
		"http.DefaultClient":         {http.DefaultClient, false},
		"one allowing loopback":      {loopback, false},
		"not an *http.Client at all": {validDependencies().HTTP, false},
	} {
		deps := validDependencies()
		deps.HTTP = tc.client
		if _, err := wallet.New(cfg, deps); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}
