package main

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// TestGenerateWalletVPFixtures_MdocCRL checks the iso_mdl fixtures
// carry a CRL the suite can fetch and accept: the Document Signer
// certificate's distribution point is where cmd/conformance-wallet-vp
// serves the CRL, and the CRL is the issuing IACA's, signed by it.
func TestGenerateWalletVPFixtures_MdocCRL(t *testing.T) {
	const crlBase = "http://conformance-wallet-vp:8080"
	cfg, iacaPEM, err := generateWalletVPFixtures("iso_mdl", crlBase)
	if err != nil {
		t.Fatalf("generateWalletVPFixtures: %v", err)
	}
	ds, err := conformancecert.ParseCertificatePEM(cfg.MdocIssuerCertificatePEM)
	if err != nil {
		t.Fatalf("parse document signer: %v", err)
	}
	iaca, err := conformancecert.ParseCertificatePEM(iacaPEM)
	if err != nil {
		t.Fatalf("parse iaca: %v", err)
	}
	want := crlBase + conformancecert.MdocCRLPath
	if len(ds.CRLDistributionPoints) != 1 || ds.CRLDistributionPoints[0] != want {
		t.Errorf("CRLDistributionPoints = %v, want [%s]", ds.CRLDistributionPoints, want)
	}
	if cfg.MdocCRLListenAddr != mdocCRLListenAddr {
		t.Errorf("MdocCRLListenAddr = %q, want %q", cfg.MdocCRLListenAddr, mdocCRLListenAddr)
	}
	der, err := conformancecert.ParseCRLPEM(cfg.MdocCRLPEM)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if !bytes.Equal(crl.RawIssuer, ds.RawIssuer) {
		t.Error("CRL issuer is not the Document Signer certificate's issuer")
	}
	if err := crl.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
}
