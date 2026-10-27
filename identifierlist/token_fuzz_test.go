package identifierlist

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// FuzzVerifyToken exercises VerifyToken against arbitrary bytes: an
// identifier list is fetched from a uri an MSO names, so its endpoint
// may be malicious.
func FuzzVerifyToken(f *testing.F) {
	ca, caKey := testcert.CA(f, "fuzz CA")
	leaf, key := testcert.Leaf(f, "fuzz signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	exp := time.Now().Add(time.Hour).Unix()
	valid, err := IssueToken(key, cose.ES256, TokenClaims{
		Sub: testURI, Iat: time.Now().Unix(), Exp: &exp, Identifiers: [][]byte{{0xcc, 0xcc}},
	}, []*x509.Certificate{leaf}, IssueOptions{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add(valid[:len(valid)-1])
	f.Fuzz(func(t *testing.T, token []byte) {
		_, _ = VerifyToken(context.Background(), token, roots, VerifyOptions{})
	})
}
