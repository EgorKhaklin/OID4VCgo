package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An mdoc's revocation list must be signed under the IACA that signed
// its document signer (ISO/IEC 18013-5 §12.3.6), not under another IACA
// the verifier also trusts; or under the Certificate its MSO's status
// names; or by a Status Issuer the policy accepts.
func TestRequireValidStatus_MdocSignerUnderTheDocumentSignersIACA(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	named, namedKey := testcert.CA(t, "the MSO's status certificate")
	ds, _ := testcert.Leaf(t, "document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(other)

	signers := map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{}
	for path, ca := range map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{"/same": {iaca, iacaKey}, "/other": {other, otherKey}, "/named": {named, namedKey}} {
		cert, key := testcert.Leaf(t, "status signer "+path, ca.cert, ca.key)
		signers[path] = struct {
			cert *x509.Certificate
			key  *ecdsa.PrivateKey
		}{cert, key}
	}
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signer, ok := signers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
			return
		}
		exp := time.Now().Add(time.Hour).Unix()
		token, err := statuslist.IssueTokenCWTX5Chain(signer.key, cose.ES256, statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), Exp: &exp, StatusList: sl}, []*x509.Certificate{signer.cert})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	credential := func(path string, certificate []byte) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
			MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 0, URI: base + path, Certificate: certificate}},
			IssuerChain: [][]byte{ds.Raw},
		}}}
	}
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	ctx := context.Background()
	strict := verifier.RequireValidStatus(checker)

	if err := strict(ctx, "id", credential("/same", nil)); err != nil {
		t.Errorf("signed under the document signer's IACA: %v", err)
	}
	if err := strict(ctx, "id", credential("/other", nil)); err == nil {
		t.Error("accepted a list signed under another trusted IACA")
	}
	if err := strict(ctx, "id", credential("/named", named.Raw)); err != nil {
		t.Errorf("signed under the Certificate the MSO's status names: %v", err)
	}
	if err := strict(ctx, "id", credential("/same", named.Raw)); err == nil {
		t.Error("accepted a list not under the Certificate the MSO's status names")
	}
	delegated := verifier.RequireValidStatusFrom(checker, func(issuer string, leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if issuer == "" && leaf.Equal(signers["/other"].cert) {
			return nil
		}
		return errors.New("not a Status Issuer")
	})
	if err := delegated(ctx, "id", credential("/other", nil)); err != nil {
		t.Errorf("a Status Issuer the policy accepts: %v", err)
	}
}
