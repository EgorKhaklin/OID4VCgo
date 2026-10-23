package mdoc_test

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// An OCSP signer, a certificate whose key usage doesn't allow digital
// signatures, or one whose extended key usage leaves out the mDL
// document signer's (a reader authentication certificate's, say),
// doesn't sign mdocs; one with neither extension may.
func TestDefaultDocumentSignerPolicy(t *testing.T) {
	readerAuth := asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
	for name, tc := range map[string]struct {
		cert *x509.Certificate
		ok   bool
	}{
		"no extensions":           {&x509.Certificate{}, true},
		"digitalSignature":        {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}, true},
		"OCSP signer":             {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, false},
		"OCSP signer, no KU":      {&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}, false},
		"KU without digitalSig":   {&x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}, false},
		"CRL signer KU":           {&x509.Certificate{KeyUsage: x509.KeyUsageCRLSign}, false},
		"another EKU with digSig": {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, false},
		"reader authentication":   {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{readerAuth}}, false},
		"mDL document signer":     {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}, true},
		"mDL DS and another EKU": {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}, true},
		"mDL DS and OCSP signer": {&x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU}}, false},
	} {
		if err := mdoc.DefaultDocumentSignerPolicy(tc.cert, nil); tc.ok != (err == nil) {
			t.Errorf("%s: %v, want ok %v", name, err, tc.ok)
		}
	}
}
