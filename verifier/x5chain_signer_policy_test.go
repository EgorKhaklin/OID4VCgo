package verifier_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// Without a LeafPolicy, X5ChainIssuerKeyResolver refuses the
// certificates an IACA issues for jobs other than signing mdocs; a
// LeafPolicy that's set replaces that check.
func TestX5ChainIssuerKeyResolver_DefaultDocumentSignerPolicy(t *testing.T) {
	ca, caKey := testcert.CA(t, "IACA")
	ocsp, _ := testcert.Issue(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "OCSP responder"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}, ca, caKey)
	crlSigner, _ := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "CRL signer"}, KeyUsage: x509.KeyUsageCRLSign,
	}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	ctx := context.Background()

	for name, cert := range map[string]*x509.Certificate{"OCSP signer": ocsp, "no digitalSignature": crlSigner} {
		r := verifier.X5ChainIssuerKeyResolver{Roots: roots}
		if _, _, err := r.ResolveMdocIssuerKey(ctx, x5chainOf(cert), "org.iso.18013.5.1.mDL"); err == nil {
			t.Errorf("%s: ResolveMdocIssuerKey accepted it as a document signer", name)
		}
		if _, err := r.ResolveMdocIssuerChains(ctx, x5chainOf(cert), "org.iso.18013.5.1.mDL"); err == nil {
			t.Errorf("%s: ResolveMdocIssuerChains accepted it as a document signer", name)
		}
	}

	anySigner := verifier.X5ChainIssuerKeyResolver{Roots: roots, LeafPolicy: func(*x509.Certificate, [][]*x509.Certificate) error { return nil }}
	if _, _, err := anySigner.ResolveMdocIssuerKey(ctx, x5chainOf(ocsp), "org.iso.18013.5.1.mDL"); err != nil {
		t.Errorf("with a LeafPolicy accepting anything: %v", err)
	}
}
