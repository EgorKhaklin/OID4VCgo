package readerauth

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A reader certificate carrying EKU is refused under an intermediate CA
// whose own extended key usage restricts it to another role, and
// accepted under one that allows it.
func TestRequireEKU_IntermediateRestriction(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	otherRole := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	for name, tc := range map[string]struct {
		intermediateEKUs []asn1.ObjectIdentifier
		ok               bool
	}{
		"intermediate restricted to another role": {[]asn1.ObjectIdentifier{otherRole}, false},
		"intermediate allowing reader auth":       {[]asn1.ObjectIdentifier{otherRole, EKU}, true},
		"intermediate without an EKU extension":   {nil, true},
	} {
		mid, midKey := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "reader CA"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, UnknownExtKeyUsage: tc.intermediateEKUs,
		}, root, rootKey)
		leaf, _ := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "reader"}, KeyUsage: x509.KeyUsageDigitalSignature,
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{EKU},
		}, mid, midKey)
		_, err := VerifyTrust([][]byte{leaf.Raw, mid.Raw}, Trust{Roots: roots, LeafPolicy: RequireEKU})
		if tc.ok != (err == nil) {
			t.Errorf("%s: VerifyTrust = %v, want ok %v", name, err, tc.ok)
		}
	}
}
