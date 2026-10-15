package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// namedSigner is a certificate under ca naming uri, and its key.
func namedSigner(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, uri string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// A separate Status Issuer signing issuer A's status lists: the default
// RequireValidStatus refuses its list, as it refuses another issuer's;
// RequireValidStatusFrom accepts it for issuer A, the issuer it signs
// for, and still refuses it for issuer B, and anyone else's list.
func TestRequireValidStatus_DelegatedStatusIssuer(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	const issuerA, statusIssuer, issuerB = "https://issuer-a.example", "https://status.example", "https://issuer-b.example"
	signers := map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{}
	for _, name := range []string{issuerA, statusIssuer, issuerB} {
		cert, key := namedSigner(t, ca, caKey, name)
		signers[name] = struct {
			cert *x509.Certificate
			key  *ecdsa.PrivateKey
		}{cert, key}
	}
	// /a is signed by issuer A, /status by the Status Issuer, /b by
	// issuer B: each a list where index 0 is VALID.
	paths := map[string]string{"/a": issuerA, "/status": statusIssuer, "/b": issuerB}
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signer, ok := signers[paths[r.URL.Path]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
			return
		}
		token, err := statuslist.IssueTokenX5C(signer.key, jose.ES256, statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{signer.cert})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.TokenMediaType)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()
	base = srv.URL
	credential := func(iss, path string) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{Claims: map[string]any{
			"iss": iss, "status": map[string]any{"status_list": map[string]any{"idx": float64(0), "uri": base + path}},
		}}}}
	}
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	ctx := context.Background()

	strict := verifier.RequireValidStatus(checker)
	if err := strict(ctx, "id", credential(issuerA, "/a")); err != nil {
		t.Errorf("issuer A's own list: %v", err)
	}
	for _, path := range []string{"/status", "/b"} {
		if err := strict(ctx, "id", credential(issuerA, path)); err == nil || !strings.Contains(err.Error(), "issuer") {
			t.Errorf("RequireValidStatus with the list at %s: %v, want refused as not the issuer's", path, err)
		}
	}

	// The Status Issuer signs for issuer A only.
	delegated := verifier.RequireValidStatusFrom(checker, func(issuer string, leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if issuer == issuerA && slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == statusIssuer }) {
			return nil
		}
		return errors.New("not a Status Issuer for this issuer")
	})
	for name, tc := range map[string]struct {
		iss, path string
		ok        bool
	}{
		"A's credential, A's own list":        {issuerA, "/a", true},
		"A's credential, its Status Issuer's": {issuerA, "/status", true},
		"A's credential, B's list":            {issuerA, "/b", false},
		"B's credential, its own list":        {issuerB, "/b", true},
		"B's credential, A's Status Issuer's": {issuerB, "/status", false},
	} {
		if err := delegated(ctx, "id", credential(tc.iss, tc.path)); (err == nil) != tc.ok {
			t.Errorf("RequireValidStatusFrom, %s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}
