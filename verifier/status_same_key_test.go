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
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// The EU reference PID's shape: an https iss, signed from a certificate
// naming no one. Its status list, signed with the same key, is its
// issuer's own (draft-ietf-oauth-status-list §11.3); one signed by
// another certificate naming no one is still refused, with or without
// a Status Issuer policy.
func TestRequireValidStatus_SameKeyAsTheCredential(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	unnamed := func(key *ecdsa.PrivateKey) *x509.Certificate {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	issuerKey, otherKey := newKey(), newKey()
	credentialCert := unnamed(issuerKey)
	signers := map[string]*ecdsa.PrivateKey{"/same": issuerKey, "/other": otherKey}

	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := signers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
			return
		}
		// A certificate of its own, naming no one: the binding is the key.
		token, err := statuslist.IssueTokenX5C(key, jose.ES256, statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{unnamed(key)})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.TokenMediaType)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()
	base = srv.URL
	credential := func(path string) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
			Claims: map[string]any{
				"iss":    "https://backend.issuer.example",
				"status": map[string]any{"status_list": map[string]any{"idx": float64(0), "uri": base + path}},
			},
			IssuerChain: [][]byte{credentialCert.Raw},
		}}}
	}
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	noStatusIssuers := func(string, *x509.Certificate, [][]*x509.Certificate) error { return errors.New("no Status Issuers") }
	ctx := context.Background()
	for name, check := range map[string]func(context.Context, string, verifier.VerifyResponseResult) error{
		"RequireValidStatus":     verifier.RequireValidStatus(checker),
		"RequireValidStatusFrom": verifier.RequireValidStatusFrom(checker, noStatusIssuers),
	} {
		if err := check(ctx, "id", credential("/same")); err != nil {
			t.Errorf("%s, signed with the credential's key: %v", name, err)
		}
		if err := check(ctx, "id", credential("/other")); err == nil {
			t.Errorf("%s accepted a list signed by another key whose certificate names no one", name)
		}
	}
}
