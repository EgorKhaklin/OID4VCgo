package certchain

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

var (
	roleEKU      = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
	otherRoleEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

// ekuCA is an intermediate CA under root whose extended key usage
// extension lists ekus, or that has none when ekus is nil.
func ekuCA(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, ekus ...asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "intermediate"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, UnknownExtKeyUsage: ekus,
	}, root, rootKey)
}

func TestEKUInPath(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	anyEKU := oidAnyExtendedKeyUsage
	for name, tc := range map[string]struct {
		intermediateEKUs []asn1.ObjectIdentifier // nil: no extension
		hasIntermediate  bool
		leafEKUs         []asn1.ObjectIdentifier
		ok               bool
	}{
		"leaf with the EKU, under the root":          {nil, false, []asn1.ObjectIdentifier{roleEKU}, true},
		"leaf without the EKU":                       {nil, false, []asn1.ObjectIdentifier{otherRoleEKU}, false},
		"leaf with no EKU extension":                 {nil, false, nil, false},
		"intermediate without an EKU extension":      {nil, true, []asn1.ObjectIdentifier{roleEKU}, true},
		"intermediate listing the EKU":               {[]asn1.ObjectIdentifier{otherRoleEKU, roleEKU}, true, []asn1.ObjectIdentifier{roleEKU}, true},
		"intermediate listing anyExtendedKeyUsage":   {[]asn1.ObjectIdentifier{anyEKU}, true, []asn1.ObjectIdentifier{roleEKU}, true},
		"intermediate restricted to another role":    {[]asn1.ObjectIdentifier{otherRoleEKU}, true, []asn1.ObjectIdentifier{roleEKU}, false},
		"leaf with anyExtendedKeyUsage, not the EKU": {nil, false, []asn1.ObjectIdentifier{anyEKU}, false},
	} {
		t.Run(name, func(t *testing.T) {
			parent, parentKey := root, rootKey
			var mid *x509.Certificate
			if tc.hasIntermediate {
				mid, parentKey = ekuCA(t, root, rootKey, tc.intermediateEKUs...)
				parent = mid
			}
			leaf, _ := testcert.Issue(t, &x509.Certificate{
				Subject: pkix.Name{CommonName: "leaf"}, KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: tc.leafEKUs,
			}, parent, parentKey)
			ders := [][]byte{leaf.Raw}
			if mid != nil {
				ders = append(ders, mid.Raw)
			}
			verified, chains, err := VerifyChains(ders, roots)
			if err != nil {
				t.Fatalf("VerifyChains: %v", err)
			}
			if err := EKUInPath(verified, chains, roleEKU); tc.ok != (err == nil) {
				t.Errorf("EKUInPath = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

// With no paths, EKUInPath checks the leaf alone.
func TestEKUInPath_NoChains(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	leaf, _ := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "leaf"}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{roleEKU},
	}, root, rootKey)
	if err := EKUInPath(leaf, nil, roleEKU); err != nil {
		t.Errorf("EKUInPath: %v", err)
	}
	if err := EKUInPath(leaf, nil, otherRoleEKU); err == nil {
		t.Error("EKUInPath accepted a leaf without the EKU")
	}
}
