package certchain

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// systemPoolOrSkip is a fresh copy of the system root pool, skipping
// where there's none to detect.
func systemPoolOrSkip(t *testing.T) *x509.CertPool {
	t.Helper()
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system root pool: %v", err)
	}
	if !platformVerified() && len(systemSubjects()) == 0 {
		t.Skip("the system root pool is empty")
	}
	return system
}

// The system pool is detected as it is, and with certificates added to
// it — the usual way to trust a private CA on top of the Web PKI.
func TestIsSystemPool(t *testing.T) {
	ca, _ := testcert.CA(t, "private CA")
	if IsSystemPool(nil) {
		t.Error("nil: reported")
	}
	private := x509.NewCertPool()
	private.AddCert(ca)
	if IsSystemPool(private) {
		t.Error("a pool of a private CA: reported")
	}
	if IsSystemPool(x509.NewCertPool()) {
		t.Error("an empty pool: reported")
	}

	if !IsSystemPool(systemPoolOrSkip(t)) {
		t.Error("the system pool: not reported")
	}
	// Where the system pool is a set of certificates, one built from it
	// is reported too; where it defers to the platform verifier, there
	// are no certificates to compare, and it isn't (IsSystemPool).
	want := !platformVerified()
	added := systemPoolOrSkip(t)
	added.AddCert(ca)
	if IsSystemPool(added) != want {
		t.Errorf("the system pool with AddCert: reported %v, want %v", !want, want)
	}
	appended := systemPoolOrSkip(t)
	if !appended.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})) {
		t.Fatal("AppendCertsFromPEM added nothing")
	}
	if IsSystemPool(appended) != want {
		t.Errorf("the system pool with AppendCertsFromPEM: reported %v, want %v", !want, want)
	}
}

// Where the system pool is a set of certificates (Linux), a pool is
// reported when it holds every one of their subjects.
func TestHoldsAll(t *testing.T) {
	a, _ := testcert.CA(t, "Web PKI root A")
	b, _ := testcert.CA(t, "Web PKI root B")
	extra, _ := testcert.CA(t, "private CA")
	want := map[string]bool{string(a.RawSubject): true, string(b.RawSubject): true}
	pool := func(certs ...*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range certs {
			p.AddCert(c)
		}
		return p
	}
	for name, tc := range map[string]struct {
		pool *x509.CertPool
		want map[string]bool
		ok   bool
	}{
		"the same certificates":     {pool(a, b), want, true},
		"with a private CA added":   {pool(a, extra, b), want, true},
		"missing one":               {pool(a, extra), want, false},
		"empty":                     {pool(), want, false},
		"against no system subject": {pool(a, b), nil, false},
	} {
		if got := holdsAll(tc.pool, tc.want); got != tc.ok {
			t.Errorf("%s: %v, want %v", name, got, tc.ok)
		}
	}
}

func BenchmarkIsSystemPool(b *testing.B) {
	ca, _ := testcert.CA(b, "private CA")
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for b.Loop() {
		IsSystemPool(pool)
	}
}
