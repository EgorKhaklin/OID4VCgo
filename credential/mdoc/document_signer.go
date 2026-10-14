package mdoc

import (
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The namespaces whose issuing_country and issuing_jurisdiction name
// the country and jurisdiction of the document's issuer, which
// CheckDocumentSigner holds to the document signer certificate.
const (
	// MDLNameSpace is the mDL's (ISO/IEC 18013-5).
	MDLNameSpace = "org.iso.18013.5.1"
	// ISO23220NameSpace is ISO/IEC 23220-2's, shared by documents built
	// on it, such as the Photo ID (org.iso.23220.photoid.1).
	ISO23220NameSpace = "org.iso.23220.1"
	// EUDIPIDNameSpace is the EU Digital Identity Wallet PID's.
	EUDIPIDNameSpace = "eu.europa.ec.eudi.pid.1"
)

// issuingAuthorityNameSpaces are the namespaces CheckDocumentSigner
// checks issuing_country and issuing_jurisdiction in.
var issuingAuthorityNameSpaces = []string{MDLNameSpace, ISO23220NameSpace, EUDIPIDNameSpace}

// CheckDocumentSigner applies ISO/IEC 18013-5's checks of a verified
// mdoc against its document signer (DS) certificate, on top of
// certificate path validation and Verify's signature check. chains are
// the verified certificate paths, the DS certificate first and a trust
// anchor (IACA) last; it returns the one the checks passed on:
//
//   - the IACA's countryName equals the DS's, and so does
//     stateOrProvinceName when both carry one (§9.3.3);
//   - the MSO was signed within the DS certificate's validity
//     (§9.3.1);
//   - an issuing_country disclosed in the mDL, ISO/IEC 23220-2 or EU
//     PID namespace matches the DS's countryName, and an
//     issuing_jurisdiction the DS's stateOrProvinceName when the DS
//     has one: in each, they name the country and jurisdiction of the
//     document's issuer, whose key the DS certificate carries.
//
// Without the last, any document signer under a shared trust list
// could issue documents naming another country.
func CheckDocumentSigner(verified VerifiedMSO, chains [][]*x509.Certificate) ([]*x509.Certificate, error) {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return nil, errors.New("mdoc: no verified document signer certificate path")
	}
	ds := chains[0][0]
	if ds == nil {
		return nil, errors.New("mdoc: no verified document signer certificate path")
	}
	if signed := verified.ValidityInfo.Signed; signed.Before(ds.NotBefore) || signed.After(ds.NotAfter) {
		return nil, fmt.Errorf("mdoc: MSO signed %s, outside the document signer certificate's validity", signed.Format(time.RFC3339))
	}
	for _, ns := range issuingAuthorityNameSpaces {
		if err := checkIssuingAuthority(ns, verified.NameSpaces[ns], ds); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, chain := range chains {
		// A custom resolver's paths: an empty one, or a nil certificate,
		// verifies nothing.
		if len(chain) == 0 || slices.Contains(chain, nil) {
			lastErr = errors.New("mdoc: an empty document signer certificate path")
			continue
		}
		leaf, iaca := chain[0], chain[len(chain)-1]
		// Annex B makes countryName mandatory in both certificates: two
		// without one don't match.
		if len(iaca.Subject.Country) == 0 || !slices.Equal(iaca.Subject.Country, leaf.Subject.Country) {
			lastErr = fmt.Errorf("mdoc: document signer countryName %v differs from its IACA's %v", leaf.Subject.Country, iaca.Subject.Country)
			continue
		}
		if len(iaca.Subject.Province) > 0 && len(leaf.Subject.Province) > 0 && !slices.Equal(iaca.Subject.Province, leaf.Subject.Province) {
			lastErr = fmt.Errorf("mdoc: document signer stateOrProvinceName %v differs from its IACA's %v", leaf.Subject.Province, iaca.Subject.Province)
			continue
		}
		return chain, nil
	}
	return nil, lastErr
}

// checkIssuingAuthority checks namespace ns's issuing_country and
// issuing_jurisdiction, when disclosed, against the DS certificate's
// subject.
func checkIssuingAuthority(ns string, elements map[string]any, ds *x509.Certificate) error {
	if v, ok := elements["issuing_country"]; ok {
		country, isString := v.(string)
		if !isString || !slices.Contains(ds.Subject.Country, country) {
			return fmt.Errorf("mdoc: %s issuing_country %v doesn't match the document signer's countryName %v", ns, v, ds.Subject.Country)
		}
	}
	if v, ok := elements["issuing_jurisdiction"]; ok && len(ds.Subject.Province) > 0 {
		jurisdiction, isString := v.(string)
		if !isString || !slices.Contains(ds.Subject.Province, jurisdiction) {
			return fmt.Errorf("mdoc: %s issuing_jurisdiction %v doesn't match the document signer's stateOrProvinceName %v", ns, v, ds.Subject.Province)
		}
	}
	return nil
}
