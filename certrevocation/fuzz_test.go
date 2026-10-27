package certrevocation_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// FuzzCRLAcceptance feeds arbitrary bytes, as a distribution point's
// response, to a Refresher and checks a chain against what it then
// holds. Nothing may panic; a list is held only when it's one the CA
// signed, complete and current, so the check then decides (nil or
// ErrRevoked), and otherwise the check fails closed with
// ErrNoCurrentCRL. CRLs over the parsed list, held or not, must
// decide the same way or fail closed.
func FuzzCRLAcceptance(f *testing.F) {
	ca, caKey := testcert.CA(f, "fuzz CA")
	leaf, _ := testcert.Leaf(f, "fuzz leaf", ca, caKey)
	other, otherKey := testcert.CA(f, "another CA")
	clean := testcert.CRL(f, ca, caKey)
	f.Add(clean.Raw)
	f.Add(testcert.CRL(f, ca, caKey, leaf.SerialNumber).Raw)
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: clean.Raw}))
	f.Add(testcert.CRL(f, other, otherKey).Raw)
	f.Add(testcert.CRLFromTemplate(f, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now().Add(-3 * time.Hour), NextUpdate: time.Now().Add(-time.Hour)}, ca, caKey).Raw)
	f.Add([]byte("-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"))
	f.Add([]byte{0x30, 0x82, 0x01})

	const u = "https://crl.example.com/ca.crl"
	check := certrevocation.Check{Chain: []*x509.Certificate{leaf, ca}}
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := certrevocation.NewRefresher(certrevocation.RefresherConfig{URLs: []string{u}, Issuers: []*x509.Certificate{ca}})
		if err != nil {
			t.Fatal(err)
		}
		acceptErr := r.AcceptForTest(u, body)
		lists, _ := r.Lists(context.Background())
		checkErr := r.Checker().CheckRevocation(context.Background(), check)
		if acceptErr != nil {
			if len(lists) != 0 {
				t.Fatalf("a refused list (%v) is held", acceptErr)
			}
			if !errors.Is(checkErr, certrevocation.ErrNoCurrentCRL) {
				t.Fatalf("with no list held, CheckRevocation = %v, want ErrNoCurrentCRL", checkErr)
			}
		} else {
			if len(lists) != 1 || lists[0].CheckSignatureFrom(ca) != nil || lists[0].NextUpdate.IsZero() {
				t.Fatalf("accepted a list the CA didn't sign, or without nextUpdate")
			}
			if checkErr != nil && !errors.Is(checkErr, certrevocation.ErrRevoked) {
				t.Fatalf("with an accepted list held, CheckRevocation = %v, want nil or ErrRevoked", checkErr)
			}
		}

		// The same bytes handed to CRLs directly, as a deployment with
		// its own fetching would.
		list, err := x509.ParseRevocationList(body)
		if err != nil {
			return
		}
		direct := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
			return []*x509.RevocationList{list}, nil
		}}.CheckRevocation(context.Background(), check)
		if direct != nil && !errors.Is(direct, certrevocation.ErrRevoked) && !errors.Is(direct, certrevocation.ErrNoCurrentCRL) {
			t.Fatalf("CRLs.CheckRevocation = %v, want nil, ErrRevoked or ErrNoCurrentCRL", direct)
		}
		if acceptErr == nil && (direct == nil) != (checkErr == nil) {
			t.Fatalf("CRLs over the accepted list = %v, Refresher's Checker = %v; want the same decision", direct, checkErr)
		}
	})
}
