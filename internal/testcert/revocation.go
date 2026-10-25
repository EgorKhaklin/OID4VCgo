package testcert

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// CRLs is a certrevocation.CRLs holding one CRL from issuer/key, current
// as CRL's are, revoking the certificates given.
func CRLs(t testing.TB, issuer *x509.Certificate, key crypto.Signer, revoked ...*x509.Certificate) certrevocation.CRLs {
	t.Helper()
	serials := make([]*big.Int, 0, len(revoked))
	for _, cert := range revoked {
		serials = append(serials, cert.SerialNumber)
	}
	return ListsOf(CRL(t, issuer, key, serials...))
}

// ListsOf is a certrevocation.CRLs holding lists.
func ListsOf(lists ...*x509.RevocationList) certrevocation.CRLs {
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return lists, nil
	}}
}

// RevocationCase is one of RevocationCases: a Checker for the role under
// test, and what verifying with it must do.
type RevocationCase struct {
	Name    string
	Checker certrevocation.Checker
	// Want is nil when the certificate must be accepted, else the error
	// errors.Is must find in the refusal.
	Want error
}

// Check fails t unless err is what c wants.
func (c RevocationCase) Check(t testing.TB, err error) {
	t.Helper()
	switch {
	case c.Want == nil && err != nil:
		t.Fatalf("%s: refused: %v", c.Name, err)
	case c.Want != nil && !errors.Is(err, c.Want):
		t.Fatalf("%s: err = %v, want %v", c.Name, err, c.Want)
	}
}

// RevocationCases are the cases each role's revocation check is tested
// with, for a certificate revoked that issuer/key issued: no Checker
// (nil: accepted, nothing checked), a current CRL naming another
// certificate (accepted), one naming revoked (ErrRevoked), and one past
// its nextUpdate (ErrNoCurrentCRL: a stale list fails closed).
func RevocationCases(t testing.TB, issuer *x509.Certificate, key crypto.Signer, revoked *x509.Certificate) []RevocationCase {
	t.Helper()
	stale := CRLFromTemplate(t, &x509.RevocationList{
		ThisUpdate: time.Now().Add(-3 * time.Hour), NextUpdate: time.Now().Add(-time.Hour),
	}, issuer, key)
	return []RevocationCase{
		{Name: "nil", Checker: nil},
		{Name: "clean", Checker: CRLs(t, issuer, key)},
		{Name: "revoked", Checker: CRLs(t, issuer, key, revoked), Want: certrevocation.ErrRevoked},
		{Name: "stale", Checker: ListsOf(stale), Want: certrevocation.ErrNoCurrentCRL},
	}
}

// RunRevocationCases runs verify with each of RevocationCases as a
// subtest, checking its error.
func RunRevocationCases(t *testing.T, issuer *x509.Certificate, key crypto.Signer, revoked *x509.Certificate, verify func(t *testing.T, revocation certrevocation.Checker) error) {
	t.Helper()
	for _, c := range RevocationCases(t, issuer, key, revoked) {
		t.Run(c.Name, func(t *testing.T) {
			c.Check(t, verify(t, c.Checker))
		})
	}
}
