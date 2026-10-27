package verifier_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// Without a LeafPolicy, X5CIssuerKeyResolver refuses a certificate
// whose key usage denotes another role — a TLS server's under an
// ecosystem CA that also issues those — and accepts one with no key
// usage, or with any purpose that may be an issuer's.
func TestX5CIssuerKeyResolver_DefaultLeafPolicy(t *testing.T) {
	ca, caKey := testcert.CA(t, "ecosystem CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	issue := func(tmpl x509.Certificate) *x509.Certificate {
		tmpl.Subject = pkix.Name{CommonName: "leaf"}
		cert, _ := testcert.Issue(t, &tmpl, ca, caKey)
		return cert
	}
	private := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	for name, tc := range map[string]struct {
		cert   *x509.Certificate
		refuse bool
	}{
		"a TLS server's": {issue(x509.Certificate{
			DNSNames: []string{"attacker.example"}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}), true},
		"TLS client and server": {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}), true},
		"code signing":          {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}), true},
		"email and time stamping": {issue(x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageTimeStamping},
		}), true},
		"an OCSP signer's":          {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageAny}}), true},
		"no digital signature":      {issue(x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}), true},
		"no key usage":              {issue(x509.Certificate{}), false},
		"digital signature only":    {issue(x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}), false},
		"any purpose":               {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}), false},
		"a private purpose":         {issue(x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{private}}), false},
		"TLS and a private purpose": {issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{private}}), false},
	} {
		_, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(tc.cert), nil)
		if tc.refuse != (err != nil) {
			t.Errorf("%s: %v, want refused %v", name, err, tc.refuse)
		}
		if policyErr := verifier.DefaultSDJWTIssuerLeafPolicy(tc.cert, nil); tc.refuse != (policyErr != nil) {
			t.Errorf("%s: DefaultSDJWTIssuerLeafPolicy: %v, want refused %v", name, policyErr, tc.refuse)
		}
	}

	// A LeafPolicy that's set replaces it.
	tls := issue(x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	resolver.LeafPolicy = func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(tls), nil); err != nil {
		t.Errorf("a LeafPolicy accepting it: %v", err)
	}
}

// Under AssuranceProduction, issuer roots that are the system root
// pool, which anchors every public CA's certificates, are refused.
func TestNewTransactions_RefusesSystemPoolIssuerRoots(t *testing.T) {
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system root pool: %v", err)
	}
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	store := assuredTransactionStore{nil}
	for name, verify := range map[string]verifier.VerifyResponseRequest{
		"issuer_keys":                     {IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"issuer_keys (pointer)":           {IssuerKeys: &verifier.X5CIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"mdoc_issuer_keys":                {MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
		"mdoc_issuer_keys RootsByDocType": {MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{RootsByDocType: map[string]*x509.CertPool{"org.iso.18013.5.1.mDL": system}, Revocation: certrevocation.NoCheck{}}},
	} {
		verify.AnyIssuerForAnyType = true
		_, err := verifier.NewTransactions(prod, store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: verify, NoStatusCheck: true})
		if err == nil || !strings.Contains(err.Error(), "system root pool") {
			t.Errorf("%s: %v, want the system root pool refused", name, err)
		}
	}
	own := x509.NewCertPool()
	ca, _ := testcert.CA(t, "issuer CA")
	own.AddCert(ca)
	verify := verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: own, Revocation: certrevocation.NoCheck{}}, AnyIssuerForAnyType: true}
	if _, err := verifier.NewTransactions(prod, store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: verify, NoStatusCheck: true}); err != nil {
		t.Errorf("the issuers' own CA: %v", err)
	}
}
