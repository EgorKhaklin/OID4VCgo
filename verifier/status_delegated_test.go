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
// RequireValidStatus refuses its list, as it refuses another issuer's,
// and an Accept naming the Status Issuer through LeafPolicy, as
// RequireValidStatus's doc describes, accepts it while still refusing
// anyone else's.
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
	credential := func(path string) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{Claims: map[string]any{
			"iss": issuerA, "status": map[string]any{"status_list": map[string]any{"idx": float64(0), "uri": base + path}},
		}}}}
	}
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	ctx := context.Background()

	strict := verifier.RequireValidStatus(checker)
	if err := strict(ctx, "id", credential("/a")); err != nil {
		t.Errorf("issuer A's own list: %v", err)
	}
	for _, path := range []string{"/status", "/b"} {
		if err := strict(ctx, "id", credential(path)); err == nil || !strings.Contains(err.Error(), "issuer") {
			t.Errorf("RequireValidStatus with the list at %s: %v, want refused as not the issuer's", path, err)
		}
	}

	// The route RequireValidStatus's doc gives a deployment with a
	// separate Status Issuer.
	delegated := checker
	delegated.Options.LeafPolicy = func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == statusIssuer }) {
			return nil
		}
		return errors.New("not the Status Issuer")
	}
	accept := func(ctx context.Context, _ string, result verifier.VerifyResponseResult) error {
		for _, vc := range result.Credentials {
			ref, cwt, ok, err := vc.StatusListRef()
			if err == nil && ok {
				err = delegated.RequireValid(ctx, ref, cwt)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := accept(ctx, "id", credential("/status")); err != nil {
		t.Errorf("the Status Issuer's list, through the delegated Accept: %v", err)
	}
	if err := accept(ctx, "id", credential("/b")); err == nil {
		t.Error("the delegated Accept took issuer B's list")
	}
}
