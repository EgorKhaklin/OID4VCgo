package mdoc

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// StatusSignerTrust is how the signer of an MSO's revocation list (its
// Status List Token or its identifier list) must be trusted, per
// ISO/IEC 18013-5 §12.3.6.2: the list carries its own x5chain, whose
// top certificate is signed either by the Certificate the MSO's status
// names or, without one, by the certificate that signed the document
// signer (for an mDL, the IACA). Another CA the reader also trusts
// can't vouch for it.
type StatusSignerTrust struct {
	// Roots, when the MSO's status names a Certificate, is a pool of
	// just that certificate: the trust point for the list's x5chain,
	// in place of the reader's roots. The MSO is issuer-signed, so it's
	// the issuer's own choice.
	Roots *x509.CertPool

	// LeafPolicy, when it doesn't, requires the list's verified path to
	// pass through the CA that signed the document signer — the CA
	// itself, not just the anchor above it, which other CAs share — for
	// a statuslist.VerifyOptions.LeafPolicy.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
}

// StatusTrust is StatusSignerTrust for ref, the MSO's status list
// reference, and documentSignerPath, the document signer's verified
// certificate path, leaf first, with or without its trust anchor. The
// CA that signed the document signer is the path's second certificate
// (matched as the same certificate, or the same subject and key), or,
// for a path of the document signer alone, the anchor that signed it.
func StatusTrust(ref *StatusListRef, documentSignerPath []*x509.Certificate) (StatusSignerTrust, error) {
	var certificate []byte
	if ref != nil {
		certificate = ref.Certificate
	}
	return revocationListTrust(certificate, documentSignerPath)
}

// IdentifierListTrust is StatusTrust for ref, the MSO's identifier list
// reference: §12.3.6.2's rule is the same for both mechanisms.
func IdentifierListTrust(ref *IdentifierListRef, documentSignerPath []*x509.Certificate) (StatusSignerTrust, error) {
	var certificate []byte
	if ref != nil {
		certificate = ref.Certificate
	}
	return revocationListTrust(certificate, documentSignerPath)
}

// revocationListTrust is StatusTrust given the Certificate the MSO's
// status reference names, empty when it names none.
func revocationListTrust(certificate []byte, documentSignerPath []*x509.Certificate) (StatusSignerTrust, error) {
	if len(certificate) > 0 {
		cert, err := x509.ParseCertificate(certificate)
		if err != nil {
			return StatusSignerTrust{}, fmt.Errorf("mdoc: status certificate: %w", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		return StatusSignerTrust{Roots: roots}, nil
	}
	if len(documentSignerPath) == 0 || documentSignerPath[0] == nil {
		return StatusSignerTrust{}, errors.New("mdoc: no document signer path to bind the revocation list's signer to")
	}
	ds := documentSignerPath[0]
	// The CA that signed the document signer, not the path's top: with
	// the anchor left off, the top is an intermediate, and any path to
	// the anchor above it — a sibling intermediate's, another issuer's —
	// would be accepted.
	signedDS := func(cert *x509.Certificate) bool { return ds.CheckSignatureFrom(cert) == nil }
	if len(documentSignerPath) > 1 {
		issuer := documentSignerPath[1]
		if issuer == nil || !signedDS(issuer) {
			return StatusSignerTrust{}, errors.New("mdoc: the document signer path's second certificate didn't sign the document signer")
		}
		// The same certificate, or the same CA certified again (a
		// cross-certificate or a renewal under the same key).
		signedDS = func(cert *x509.Certificate) bool {
			return bytes.Equal(cert.Raw, issuer.Raw) ||
				bytes.Equal(cert.RawSubject, issuer.RawSubject) && bytes.Equal(cert.RawSubjectPublicKeyInfo, issuer.RawSubjectPublicKeyInfo)
		}
	}
	return StatusSignerTrust{LeafPolicy: func(_ *x509.Certificate, chains [][]*x509.Certificate) error {
		for _, chain := range chains {
			// The list's signer is the CA that signed the document signer,
			// or under it: the path to the anchor passes through it. With
			// the document signer alone, that CA is the anchor.
			if slices.ContainsFunc(chain, signedDS) {
				return nil
			}
		}
		return errors.New("the revocation list's signer isn't under the CA that signed the document signer (ISO/IEC 18013-5 §12.3.6.2)")
	}}, nil
}

// IssuerAuthStatus reads s's MSO status and IssuerAuth x5chain without
// verifying anything: for a credential verified when it was received,
// to find how its revocation list's signer must be trusted.
func IssuerAuthStatus(s IssuerSigned) (*Status, []*x509.Certificate, error) {
	protected, unprotected, mso, err := decodeIssuerAuth(s)
	if err != nil {
		return nil, nil, err
	}
	ders := cose.X5ChainOf(protected, unprotected)
	chain := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("mdoc: IssuerAuth x5chain: %w", err)
		}
		chain = append(chain, cert)
	}
	return mso.Status, chain, nil
}

// IssuerAuthMSO reads s's MSO without verifying anything: for a
// credential verified when it was received, to compare what its MSO
// discloses to every reader (valueDigests, validityInfo) with another
// copy's.
func IssuerAuthMSO(s IssuerSigned) (MobileSecurityObject, error) {
	_, _, mso, err := decodeIssuerAuth(s)
	return mso, err
}

// decodeIssuerAuth decodes s's IssuerAuth and its MSO, unverified.
func decodeIssuerAuth(s IssuerSigned) (protected, unprotected cose.Headers, mso MobileSecurityObject, err error) {
	protected, unprotected, payload, err := cose.DecodeUnverified(s.IssuerAuth)
	if err != nil {
		return cose.Headers{}, cose.Headers{}, MobileSecurityObject{}, fmt.Errorf("mdoc: decode IssuerAuth: %w", err)
	}
	if err := unwrapTag24(payload, &mso); err != nil {
		return cose.Headers{}, cose.Headers{}, MobileSecurityObject{}, fmt.Errorf("mdoc: decode MobileSecurityObject: %w", err)
	}
	return protected, unprotected, mso, nil
}
