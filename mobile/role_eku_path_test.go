package mobile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A role's EKU policy holds the verified path to it too: a leaf with
// the role's usage is refused under an intermediate CA whose own
// extended key usage restricts it to another.
func TestRequireEKU_IntermediateRestriction(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	policy, err := roleEKU("verifier_require_eku", "1.3.6.1.5.5.7.3.2")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		intermediate []x509.ExtKeyUsage
		ok           bool
	}{
		"intermediate restricted to serverAuth": {[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		"intermediate allowing clientAuth":      {[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, true},
		"intermediate without the extension":    {nil, true},
	} {
		mid, midKey := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "intermediate"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: tc.intermediate,
		}, root, rootKey)
		leaf, _ := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "verifier"}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, mid, midKey)
		_, err := certchain.VerifyLeafWithPolicy([][]byte{leaf.Raw, mid.Raw}, roots, policy)
		if tc.ok != (err == nil) {
			t.Errorf("%s: %v, want ok %v", name, err, tc.ok)
		}
	}
}
