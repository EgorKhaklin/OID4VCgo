package conformancecert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// MdocCRLContentType is the media type RFC 2585 §4.2 registers for a
// DER-encoded CRL, which the OIDF conformance suite expects a Document
// Signer certificate's CRL distribution point to answer with.
const MdocCRLContentType = "application/pkix-crl"

// MdocCRLPath is the path a conformance binary serves its IACA's CRL
// at (see MdocCRLHandler) — the path of the CRL distribution point
// URI a driver puts in the Document Signer certificate it issues with
// GenerateMdocDocumentSigner.
const MdocCRLPath = "/mdoc-iaca.crl"

// mdocCRLValidity is the gap between a generated CRL's thisUpdate and
// nextUpdate: well within ISO/IEC 18013-5 Annex B.2's 90-day maximum
// interval between CRLs, and far longer than any conformance run.
const mdocCRLValidity = 30 * 24 * time.Hour

// mdocCRLBackdate keeps thisUpdate safely in the past for a reader
// whose clock runs slightly behind this host's.
const mdocCRLBackdate = time.Hour

// GenerateMdocCRL builds a DER-encoded, empty CRL issued and signed by
// iacaCert/iacaKey (see GenerateMdocIACA), meeting ISO/IEC 18013-5
// Annex B.2 and Table B.10: a v2 CRL whose issuer is the IACA's
// subject (so it matches a Document Signer certificate's issuer
// byte-for-byte), signed with ECDSA, with a nextUpdate 30 days after
// thisUpdate, no revokedCertificates list (nothing is revoked), and
// exactly two non-critical extensions — an authority key identifier
// in keyIdentifier form equal to the IACA's subject key identifier,
// and a CRL number. crypto/x509.CreateRevocationList produces exactly
// that shape; mdoccrl_test.go pins it.
func GenerateMdocCRL(iacaCert *x509.Certificate, iacaKey *ecdsa.PrivateKey) ([]byte, error) {
	thisUpdate := time.Now().Add(-mdocCRLBackdate).UTC().Truncate(time.Second)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(mdocCRLValidity),
	}, iacaCert, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("create mdoc crl: %w", err)
	}
	return der, nil
}

// MdocCRLPEM is GenerateMdocCRL's result PEM-encoded, for a JSON
// config file.
func MdocCRLPEM(iacaCert *x509.Certificate, iacaKey *ecdsa.PrivateKey) (string, error) {
	der, err := GenerateMdocCRL(iacaCert, iacaKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

// ParseCRLPEM decodes a single PEM "X509 CRL" block and checks it
// parses as a CRL, returning its DER encoding.
func ParseCRLPEM(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("no PEM X509 CRL block found")
	}
	if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
		return nil, fmt.Errorf("parse crl: %w", err)
	}
	return block.Bytes, nil
}

// MdocCRLHandler serves crlDER at MdocCRLPath as MdocCRLContentType,
// for a plain-HTTP listener: a CRL distribution point is conventionally
// plain http (RFC 5280 §4.2.1.13), the CRL being signed rather than
// relying on the transport.
func MdocCRLHandler(crlDER []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+MdocCRLPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", MdocCRLContentType)
		_, _ = w.Write(crlDER)
	})
	return mux
}

// ServeMdocCRL serves crlDER (see MdocCRLHandler) on addr over plain
// HTTP until the listener fails.
func ServeMdocCRL(addr string, crlDER []byte) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           MdocCRLHandler(crlDER),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}
