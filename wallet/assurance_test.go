package wallet_test

import (
	"github.com/idfoundry/fapigo/fapihttp"
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

func TestNewProductionAcceptsHardenedFetch(t *testing.T) {
	cfg := validConfig()
	cfg.Assurance = wallet.AssuranceProduction
	cfg.Fetch.AllowLoopbackHTTP = false
	// An explicit private-host allow-list is a deployment choice, not a
	// development switch, so it stays permitted.
	cfg.Fetch.AllowedPrivateHosts = []string{"issuer.internal"}
	cfg.Fetch.AllowedLoopbackHosts = []string{"issuer-sidecar.internal"}
	if _, err := wallet.New(cfg, productionDependencies()); err != nil {
		t.Fatalf("New(AssuranceProduction): %v", err)
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
