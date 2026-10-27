package verifier_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// RequireValidStatus checks an mdoc's identifier list, binding the
// list's signer to the document signer's IACA as for a status list, or
// with no issuer chain to bind it to, by a StatusIssuerPolicy.
func TestRequireValidStatus_IdentifierList(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	ds, _ := testcert.Leaf(t, "document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(other)
	sameCert, sameKey := testcert.Leaf(t, "list signer", iaca, iacaKey)
	otherCert, otherSignerKey := testcert.Leaf(t, "other list signer", other, otherKey)
	identifiers := func(context.Context) ([][]byte, error) { return [][]byte{{0xcc}}, nil }
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &identifierlist.Publisher{URI: base + r.URL.Path, Signer: sameKey, Chain: []*x509.Certificate{sameCert}, Identifiers: identifiers}
		if r.URL.Path == "/other" {
			p.Signer, p.Chain = otherSignerKey, []*x509.Certificate{otherCert}
		}
		p.ServeHTTP(w, r)
	}))
	defer srv.Close()
	base = srv.URL
	credential := func(path string, id byte, chain [][]byte) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
			MdocStatus:  &mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{ID: []byte{id}, URI: base + path}},
			IssuerChain: chain,
		}}}
	}
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	accept := verifier.RequireValidStatus(checker)
	ctx := context.Background()
	dsChain := [][]byte{ds.Raw}

	if err := accept(ctx, "id", credential("/same", 0xcd, dsChain)); err != nil {
		t.Errorf("not on a list signed under the document signer's IACA: %v", err)
	}
	if err := accept(ctx, "id", credential("/same", 0xcc, dsChain)); !errors.Is(err, identifierlist.ErrRevoked) {
		t.Errorf("on the list: %v, want ErrRevoked", err)
	}
	anySigner := verifier.RequireValidStatusFrom(checker, verifier.AnyStatusListSigner)
	if err := anySigner(ctx, "id", credential("/other", 0xcd, nil)); err != nil {
		t.Errorf("no issuer chain, AnyStatusListSigner: %v", err)
	}
	// A Certificate the MSO's reference names is the list signer's sole
	// trust anchor (ISO/IEC 18013-5 §12.3.6.2): it binds the signer with
	// no issuer chain and no StatusIssuerPolicy.
	pinned := func(path string, id byte, pin *x509.Certificate) verifier.VerifyResponseResult {
		r := credential(path, id, nil)
		r.Credentials[0].MdocStatus.IdentifierList.Certificate = pin.Raw
		return r
	}
	if err := accept(ctx, "id", pinned("/same", 0xcd, iaca)); err != nil {
		t.Errorf("pinned to the signer's IACA: %v", err)
	}
	if err := accept(ctx, "id", pinned("/same", 0xcc, iaca)); !errors.Is(err, identifierlist.ErrRevoked) {
		t.Errorf("pinned, on the list: %v, want ErrRevoked", err)
	}
	refusing := verifier.RequireValidStatusFrom(checker, func(string, *x509.Certificate, [][]*x509.Certificate) error { return errors.New("not a Status Issuer") })
	if err := refusing(ctx, "id", credential("/other", 0xcd, nil)); err == nil || !strings.Contains(err.Error(), "not a Status Issuer") {
		t.Errorf("no issuer chain, a StatusIssuerPolicy refusing: %v", err)
	}
	// The handler serves only identifier lists, so its status list can't
	// be read.
	withStatusList := credential("/same", 0xcd, dsChain)
	withStatusList.Credentials[0].MdocStatus.StatusList = &mdoc.StatusListRef{URI: base + "/statuslist"}
	for name, tc := range map[string]struct {
		result verifier.VerifyResponseResult
		want   string
	}{
		"signed under another IACA":     {credential("/other", 0xcd, dsChain), "isn't under the CA that signed the document signer"},
		"no issuer chain":               {credential("/same", 0xcd, nil), "can't be bound to its issuer"},
		"pinned to another IACA":        {pinned("/same", 0xcd, other), "token signer"},
		"and an unreadable status list": {withStatusList, "statuslist: fetch"},
	} {
		err := accept(ctx, "id", tc.result)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, tc.want)
		}
	}
}
