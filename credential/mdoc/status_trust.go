package mdoc

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// StatusSignerTrust is how the signer of an MSO's revocation list (its
// Status List Token) must be trusted, per ISO/IEC 18013-5 §12.3.6: the
// list carries its own x5chain, whose top certificate is signed either
// by the Certificate the MSO's status names or, without one, by the
// certificate that signed the document signer (for an mDL, the IACA).
// Another CA the reader also trusts can't vouch for it.
type StatusSignerTrust struct {
	// Roots, when the MSO's status names a Certificate, is a pool of
	// just that certificate: the trust point for the list's x5chain,
	// in place of the reader's roots. The MSO is issuer-signed, so it's
	// the issuer's own choice.
	Roots *x509.CertPool

	// LeafPolicy, when it doesn't, requires the list's verified path to
	// end at the CA that signed the document signer's path, for a
	// statuslist.VerifyOptions.LeafPolicy.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
}

// StatusTrust is StatusSignerTrust for ref, the MSO's status list
// reference, and documentSignerPath, the document signer's verified
// certificate path, leaf first, with or without its trust anchor.
func StatusTrust(ref *StatusListRef, documentSignerPath []*x509.Certificate) (StatusSignerTrust, error) {
	if ref != nil && len(ref.Certificate) > 0 {
		cert, err := x509.ParseCertificate(ref.Certificate)
		if err != nil {
			return StatusSignerTrust{}, fmt.Errorf("mdoc: status certificate: %w", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		return StatusSignerTrust{Roots: roots}, nil
	}
	if len(documentSignerPath) == 0 || documentSignerPath[len(documentSignerPath)-1] == nil {
		return StatusSignerTrust{}, errors.New("mdoc: no document signer path to bind the status list's signer to")
	}
	top := documentSignerPath[len(documentSignerPath)-1]
	return StatusSignerTrust{LeafPolicy: func(_ *x509.Certificate, chains [][]*x509.Certificate) error {
		for _, chain := range chains {
			if len(chain) == 0 {
				continue
			}
			root := chain[len(chain)-1]
			// The path's anchor is the CA that signed the document signer's
			// path, or is that path's own top certificate when it carries
			// its anchor.
			if bytes.Equal(root.Raw, top.Raw) || top.CheckSignatureFrom(root) == nil {
				return nil
			}
		}
		return errors.New("the status list's signer isn't under the CA that signed the document signer (ISO/IEC 18013-5 §12.3.6)")
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
