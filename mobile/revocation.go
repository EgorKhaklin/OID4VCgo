package mobile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// crlSet holds the Certificate Revocation Lists the revocation checks
// of a Wallet or ProximityReader read, replaced whole by SetCRLs: CRLs
// expire (their nextUpdate), so an app fetches fresh ones and hands
// them over without rebuilding the wallet.
type crlSet struct {
	lists atomic.Pointer[[]*x509.RevocationList]
}

// newCRLSet is a crlSet holding the CRLs of the config key name's PEM.
func newCRLSet(name, pemText string) (*crlSet, error) {
	s := &crlSet{}
	if err := s.set(pemText); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("%s: %w", name, err))
	}
	return s, nil
}

// set replaces s's lists with pemText's.
func (s *crlSet) set(pemText string) error {
	lists, err := parseCRLs(pemText)
	if err != nil {
		return err
	}
	s.lists.Store(&lists)
	return nil
}

// checker is a certrevocation.CRLs over s's current lists. With none
// that apply, it fails closed (certrevocation.ErrNoCurrentCRL).
func (s *crlSet) checker() certrevocation.CRLs {
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		if p := s.lists.Load(); p != nil {
			return *p, nil
		}
		return nil, nil
	}}
}

// maxCRLs bounds how many lists one PEM text may hold: each is checked
// on every certificate chain a role verifies.
const maxCRLs = 64

// parseCRLs parses pemText's "X509 CRL" blocks. Anything else — another
// block type, text outside the blocks, a list that doesn't parse — is
// refused, so a certificate pasted in place of a CRL isn't silently
// dropped. Empty text is no lists.
func parseCRLs(pemText string) ([]*x509.RevocationList, error) {
	var lists []*x509.RevocationList
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("PEM block %d is %q, not an X509 CRL", len(lists), block.Type)
		}
		list, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CRL %d: %w", len(lists), err)
		}
		if lists = append(lists, list); len(lists) > maxCRLs {
			return nil, fmt.Errorf("more than %d CRLs", maxCRLs)
		}
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("text that isn't a PEM X509 CRL block")
	}
	return lists, nil
}

// Revocation role names, the "revocation" configuration's entries.
const (
	revocationIssuer         = "issuer"
	revocationIssuerMetadata = "issuer_metadata"
	revocationRegistrar      = "registrar"
	revocationMdocReader     = "mdoc_reader"
	revocationVerifier       = "verifier"
	revocationStatus         = "status"
)

// revocationRoles checks roles, a "revocation" configuration, names
// only roles in known, each once, and returns whether each known role
// is named.
func revocationRoles(roles []string, known ...string) (map[string]bool, error) {
	named := make(map[string]bool, len(roles))
	for _, r := range roles {
		switch {
		case !slices.Contains(known, r):
			return nil, newError(CodeInvalidInput, fmt.Errorf("revocation: %q isn't a role: want one of %q", r, known))
		case named[r]:
			return nil, newError(CodeInvalidInput, fmt.Errorf("revocation: %q is named twice", r))
		}
		named[r] = true
	}
	return named, nil
}
