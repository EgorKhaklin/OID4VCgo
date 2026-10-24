package wallet_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Without an IssuerLeafPolicy, an mdoc signed by an OCSP signer's
// certificate under the IACA is refused (mdoc.DefaultDocumentSignerPolicy);
// an IssuerLeafPolicy that's set replaces the check.
func TestVerifyIssuedCredential_MdocDefaultSignerPolicy(t *testing.T) {
	ca, caKey := testcert.CAWithSubject(t, pkix.Name{CommonName: "IACA", Country: []string{"SG"}})
	ocsp, ocspKey := testcert.Issue(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "OCSP responder", Country: []string{"SG"}},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := newIssuedFixture(t, ocsp, ocspKey, roots)
	params := wallet.VerifyIssuedCredentialParams{
		Configuration: f.mdocConf, Credential: f.mdocB, HolderKey: &f.holder.PublicKey, IssuerRoots: roots,
	}
	if _, err := wallet.VerifyIssuedCredential(context.Background(), params); err == nil {
		t.Error("an mdoc signed by an OCSP signer's certificate was accepted")
	}
	params.IssuerLeafPolicy = func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	if _, err := wallet.VerifyIssuedCredential(context.Background(), params); err != nil {
		t.Errorf("with an IssuerLeafPolicy accepting anything: %v", err)
	}
}
