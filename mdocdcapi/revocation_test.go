package mdocdcapi

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
)

// ReaderTrust.Revocation leaves a reader whose certificate is revoked
// unrecognized: ErrUntrustedReader, wrapping certrevocation.ErrRevoked.
func TestVerifyReaderTrust_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "mdocdcapi revocation test reader CA")
	cert, key := testcert.Leaf(t, "mdocdcapi revocation test reader", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	reader := ReaderKey{Signer: key, Chain: []*x509.Certificate{cert}}
	req, err := BuildRequest(RequestParams{Origin: testOrigin, DocType: testmdoc.DocType, Elements: bothNames(), Readers: []ReaderKey{reader}})
	if err != nil {
		t.Fatal(err)
	}
	in, err := ParseRequest(marshalData(t, req.Data), testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	testcert.RunRevocationCases(t, ca, caKey, cert, func(t *testing.T, revocation certrevocation.Checker) error {
		_, err := in.VerifyReaderTrust(ReaderTrust{Roots: roots, Revocation: revocation})
		if err != nil && !errors.Is(err, ErrUntrustedReader) {
			t.Errorf("err = %v, want it to wrap ErrUntrustedReader", err)
		}
		return err
	})
}
