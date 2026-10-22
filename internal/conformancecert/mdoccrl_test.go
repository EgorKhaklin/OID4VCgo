package conformancecert_test

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// TestGenerateMdocCRL_MeetsSuiteProfile re-implements the OIDF
// conformance suite's ValidateMdocDsCertificateCrl and
// EnsureMdocDsCertificateCrlNextUpdateWithin90Days checks (ISO/IEC
// 18013-5 Annex B.2 and Table B.10), which every mdoc credential the
// suite validates now runs against the CRL named by its Document
// Signer certificate's CRL distribution point.
func TestGenerateMdocCRL_MeetsSuiteProfile(t *testing.T) {
	iacaCert, iacaKey, _, _, err := conformancecert.GenerateMdocIACA("test-mdoc-iaca", "FR", "https://example.com/contact")
	if err != nil {
		t.Fatalf("GenerateMdocIACA: %v", err)
	}
	_, _, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("test-mdoc-ds", "FR", "https://example.com/contact",
		"http://conformance-test"+conformancecert.MdocCRLPath, iacaCert, iacaKey)
	if err != nil {
		t.Fatalf("GenerateMdocDocumentSigner: %v", err)
	}
	ds, err := conformancecert.ParseCertificatePEM(dsCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(ds): %v", err)
	}

	crlPEM, err := conformancecert.MdocCRLPEM(iacaCert, iacaKey)
	if err != nil {
		t.Fatalf("MdocCRLPEM: %v", err)
	}
	der, err := conformancecert.ParseCRLPEM(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}

	if err := crl.CheckSignatureFrom(iacaCert); err != nil {
		t.Errorf("signature does not verify with the IACA certificate: %v", err)
	}
	if crl.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA256", crl.SignatureAlgorithm)
	}
	if !bytes.Equal(crl.RawIssuer, ds.RawIssuer) {
		t.Error("CRL issuer is not byte-for-byte the Document Signer certificate's issuer")
	}

	now := time.Now()
	if crl.ThisUpdate.After(now) {
		t.Errorf("thisUpdate %v is in the future", crl.ThisUpdate)
	}
	if !crl.NextUpdate.After(now) {
		t.Errorf("nextUpdate %v has passed", crl.NextUpdate)
	}
	if gap := crl.NextUpdate.Sub(crl.ThisUpdate); gap > 90*24*time.Hour {
		t.Errorf("nextUpdate is %v after thisUpdate, want at most 90 days", gap)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("CRL revokes %d certificates, want none", len(crl.RevokedCertificateEntries))
	}

	checkCRLExtensions(t, crl, iacaCert, ds)
	checkCRLTBS(t, der)
}

// checkCRLExtensions: exactly a non-critical authority key identifier
// (keyIdentifier form, equal to the IACA's subject key identifier and
// the Document Signer's authority key identifier) and a non-critical,
// non-negative CRL number of at most 20 octets.
func checkCRLExtensions(t *testing.T, crl *x509.RevocationList, iaca, ds *x509.Certificate) {
	t.Helper()
	seen := map[string]bool{}
	for _, ext := range crl.Extensions {
		seen[ext.Id.String()] = true
		if ext.Critical {
			t.Errorf("extension %s is critical", ext.Id)
		}
		switch ext.Id.String() {
		case "2.5.29.35", "2.5.29.20":
		default:
			t.Errorf("unexpected extension %s", ext.Id)
		}
	}
	if !seen["2.5.29.35"] || !seen["2.5.29.20"] {
		t.Errorf("extensions = %v, want authority key identifier and CRL number", seen)
	}
	if !bytes.Equal(crl.AuthorityKeyId, iaca.SubjectKeyId) || !bytes.Equal(crl.AuthorityKeyId, ds.AuthorityKeyId) {
		t.Error("authority key identifier does not match the IACA's subject key identifier")
	}
	if crl.Number == nil || crl.Number.Sign() < 0 || len(crl.Number.Bytes()) > 20 {
		t.Errorf("CRL number = %v, want a non-negative integer of at most 20 octets", crl.Number)
	}
}

// checkCRLTBS reads the TBSCertList (RFC 5280 §5.1) directly: version
// v2, a signature algorithm equal to the outer one, and no
// revokedCertificates SEQUENCE at all (Table B.10 forbids an empty
// one, which crypto/x509's parsed view can't tell from an absent one).
func checkCRLTBS(t *testing.T, der []byte) {
	t.Helper()
	var certList struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &certList); err != nil || len(rest) != 0 {
		t.Fatalf("malformed CertificateList: %v", err)
	}
	var fields []asn1.RawValue
	for rest := certList.TBS.Bytes; len(rest) > 0; {
		var field asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &field); err != nil {
			t.Fatalf("malformed TBSCertList: %v", err)
		}
		fields = append(fields, field)
	}
	// version, signature, issuer, thisUpdate, nextUpdate, then only
	// the [0] crlExtensions.
	if len(fields) != 6 {
		t.Fatalf("TBSCertList has %d fields, want 6", len(fields))
	}
	var version int
	if _, err := asn1.Unmarshal(fields[0].FullBytes, &version); err != nil || version != 1 {
		t.Errorf("TBSCertList version = %d (%v), want 1 (v2)", version, err)
	}
	if !bytes.Equal(fields[1].FullBytes, certList.SigAlg.FullBytes) {
		t.Error("TBSCertList signature algorithm differs from the CRL's")
	}
	if fields[5].Class != asn1.ClassContextSpecific || fields[5].Tag != 0 {
		t.Error("TBSCertList carries a revokedCertificates list, or no crlExtensions")
	}
}

func TestMdocCRLHandler(t *testing.T) {
	crl := []byte{0x30, 0x00}
	srv := httptest.NewServer(conformancecert.MdocCRLHandler(crl))
	defer srv.Close()

	resp, err := http.Get(srv.URL + conformancecert.MdocCRLPath)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != conformancecert.MdocCRLContentType {
		t.Errorf("Content-Type = %q, want %q", ct, conformancecert.MdocCRLContentType)
	}
	if !bytes.Equal(body, crl) {
		t.Errorf("body = %x, want %x", body, crl)
	}

	resp, err = http.Get(srv.URL + "/other")
	if err != nil {
		t.Fatalf("GET /other: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /other status = %d, want 404", resp.StatusCode)
	}
}

func TestParseCRLPEM_RejectsNonCRL(t *testing.T) {
	certPEM, _, err := conformancecert.SelfSignedPEM("x", []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conformancecert.ParseCRLPEM(certPEM); err == nil {
		t.Error("ParseCRLPEM accepted a certificate")
	}
}
