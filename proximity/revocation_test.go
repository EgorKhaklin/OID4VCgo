package proximity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// WithIssuerRevocation refuses a document whose document signer
// certificate is revoked.
func TestVerify_IssuerRevocation(t *testing.T) {
	fx := issueFixture(t, mDL)
	testcert.RunRevocationCases(t, fx.ca, fx.caKey, fx.signer, func(t *testing.T, revocation certrevocation.Checker) error {
		f := establishReader(t, mDL, ageOver18, WithIssuerRevocation(revocation))
		_, err := f.reader.Verify(f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
		return err
	})
	if _, err := NewReaderSession(mustQR(t), WithIssuerRevocation(certrevocation.CRLs{})); err == nil {
		t.Error("NewReaderSession accepted CRLs without Lists")
	}
}

// ReaderTrust.Revocation leaves a reader whose certificate is revoked
// untrusted.
func TestVerifyReaderAuth_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "proximity revocation test reader CA")
	cert, key := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "proximity revocation test reader"}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := establishReader(t, mDL, ageOver18, WithReaderAuth(key, []*x509.Certificate{cert}))
	testcert.RunRevocationCases(t, ca, caKey, cert, func(t *testing.T, revocation certrevocation.Checker) error {
		got := f.holder.VerifyReaderAuth(f.req, ReaderTrust{Roots: roots, Revocation: revocation})
		if (got.Status == ReaderTrusted) != (got.Err == nil) {
			t.Errorf("Status %v with Err %v", got.Status, got.Err)
		}
		return got.Err
	})
}

// mustQR is a fresh holder's QR code.
func mustQR(t *testing.T) string {
	t.Helper()
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	return holder.QRCode()
}
