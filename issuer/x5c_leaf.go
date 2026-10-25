package issuer

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// resolveX5CLeaf extracts x5c (RFC 7515 §4.1.6: standard-base64-encoded
// DER certificates, leaf first, as a decoded JSON array) and verifies
// it against roots, requiring at least one entry — shared by
// X5CAttestationVerifier and X5CProofBindingKeyResolver, which differ
// only in how they got x5c from their own caller's own wire shape (a
// KeyAttestation's own []string vs a raw JOSE header's own []any).
//
// The trust anchor must not be in x5c (HAIP 1.0 §4.5.1, for a key
// attestation), and the chain is checked at the verification time ctx
// carries (the Issuer's Clock), as the rest of the request is. It
// returns the leaf and its verified paths (leaf first, anchor last)
// that policy approves each on its own and revocation passes, for a
// caller that checks which anchor a path ends at; a nil revocation
// checks none.
func resolveX5CLeaf(ctx context.Context, x5c []any, roots *x509.CertPool, policy func(*x509.Certificate, [][]*x509.Certificate) error, revocation certrevocation.Checker) (*x509.Certificate, [][]*x509.Certificate, error) {
	ders, err := presentedX5CDERs(x5c)
	if err != nil {
		return nil, nil, err
	}
	if err := certchain.ValidateRevocation(revocation); err != nil {
		return nil, nil, fmt.Errorf("issuer: Revocation: %w", err)
	}
	leaf, chains, err := certchain.VerifyTrustedChainsAt(ctx, ders, roots, policy, revocation, certchain.TimeFrom(ctx))
	if err != nil {
		return nil, nil, fmt.Errorf("issuer: %w", err)
	}
	return leaf, chains, nil
}

// presentedX5CDERs decodes x5c, requiring at least one entry and no
// trust anchor among them.
func presentedX5CDERs(x5c []any) ([][]byte, error) {
	if len(x5c) == 0 {
		return nil, fmt.Errorf("issuer: x5c must be a non-empty array")
	}
	ders, err := certchain.DERsFromBase64(x5c)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	if err := certchain.CheckNoAnchor(ders); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	return ders, nil
}
