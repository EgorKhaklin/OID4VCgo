package certrevocation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A CA revokes a certificate it issued; CRLs, holding the CA's current
// list, refuses a chain through it. In a deployment the list comes from
// the CA's CRL distribution point, refreshed in the background (see
// Refresher), and the Checker goes in a resolver's Revocation field
// (verifier.X5ChainIssuerKeyResolver, verifier.X5CIssuerKeyResolver),
// which checks every verified path itself.
func ExampleCRLs() {
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example IACA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Example document signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &dsKey.PublicKey, caKey)
	ds, _ := x509.ParseCertificate(dsDER)

	// issue is the CA's CRL, revoking the serial numbers given.
	issue := func(revoked ...*big.Int) *x509.RevocationList {
		tmpl := &x509.RevocationList{Number: big.NewInt(now.Unix()), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
		for _, serial := range revoked {
			tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: now})
		}
		der, _ := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
		list, _ := x509.ParseRevocationList(der)
		return list
	}

	// current holds the list in memory; a refresher would replace it.
	var current atomic.Pointer[x509.RevocationList]
	current.Store(issue())
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return []*x509.RevocationList{current.Load()}, nil
	}}
	check := certrevocation.Check{Chain: []*x509.Certificate{ds, ca}, Now: now}

	fmt.Println("before:", checker.CheckRevocation(context.Background(), check))
	current.Store(issue(ds.SerialNumber))
	err := checker.CheckRevocation(context.Background(), check)
	fmt.Println("after, revoked:", errors.Is(err, certrevocation.ErrRevoked))
	// Output:
	// before: <nil>
	// after, revoked: true
}

// iacaDER is the IACA certificate a verifier trusts, in DER.
var iacaDER []byte

// A Refresher keeps an IACA's CRL current in the background and hands
// it to the verifier's issuer trust, which refuses a document signer
// the IACA has revoked. The distribution point comes from the IACA's
// own certificate, configured by the deployment: never from a
// certificate a credential presents.
func ExampleRefresher() {
	iaca, err := x509.ParseCertificate(iacaDER)
	if err != nil {
		log.Fatal(err)
	}
	refresher, err := certrevocation.NewRefresher(certrevocation.RefresherConfig{
		URLs:    iaca.CRLDistributionPoints,
		Issuers: []*x509.Certificate{iaca},
		OnError: func(url string, err error) { log.Printf("CRL refresh: %v", err) },
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// Fetch once before serving, so the first verifications don't fail
	// closed, then keep the lists current until ctx ends.
	if err := refresher.Refresh(ctx); err != nil {
		log.Fatal(err)
	}
	go refresher.Run(ctx)

	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: refresher.Checker()}
	_ = verifier.VerifyResponseRequest{MdocIssuerKeys: resolver} // with the rest of the request
}
