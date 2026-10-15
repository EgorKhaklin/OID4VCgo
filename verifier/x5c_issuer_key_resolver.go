package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// X5CIssuerKeyResolver implements SDJWTVCIssuerKeyResolver by
// validating a presented "dc+sd-jwt" credential's own "x5c" header
// (RFC 7515 §4.1.6) against Roots — HAIP 1.0 §5.3's own MUST for
// "dc+sd-jwt" issuer trust, which SDJWTVCIssuerKeyResolver's own doc
// comment names as a deployment policy decision but leaves
// unimplemented anywhere in this repo. Confirmed live against the
// OpenID Foundation conformance suite's own two checks on this exact
// requirement ("Credential MUST contain an x5c in the header", "Leaf
// certificate in x5c chain must not be self-signed" —
// cmd/conformance-wallet-vp's own README) — this resolver enforces
// both on the verifying side, not just the issuing side
// credential/sdjwtvc.IssueOptions.IssuerCertificate satisfies on the
// issuing side.
//
// The issuer is the leaf's subject (SD-JWT VC, the x5c header): an
// iss must name it, as a "dns:" URI whose DNS name is one of its
// dNSName subject alternative names, or otherwise exactly one of its
// uniformResourceIdentifier names. Without an iss, the leaf is the
// issuer.
//
// A self-signed leaf is always rejected, even if that exact
// certificate also happens to be present in Roots — see
// internal/certchain.VerifyLeaf's own doc comment for why.
type X5CIssuerKeyResolver struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. REQUIRED.
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified leaf and its
	// verified paths, and can refuse it. Chain validation accepts a
	// leaf with any key usage, so a certificate issued for another role
	// under the same Roots (a relying party's, a wallet provider's)
	// would otherwise be accepted too: prefer Roots that anchor only
	// this role's certificates, and use LeafPolicy to require what
	// distinguishes them (an extended key usage, a certificate policy)
	// where the anchors are shared.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
}

// ResolveIssuerKey implements SDJWTVCIssuerKeyResolver.
func (r X5CIssuerKeyResolver) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, "", err
	}
	if err := certchain.CheckNoAnchor(ders); err != nil {
		return nil, "", err
	}
	leaf, err := certchain.VerifyLeafWithPolicyAt(ders, r.Roots, r.LeafPolicy, verificationTime(ctx))
	if err != nil {
		return nil, "", err
	}
	// The issuer is the leaf's subject (SD-JWT VC, the x5c header): an
	// iss must name it, or any issuer under Roots could sign in another
	// issuer's name.
	if issRaw, present := payload["iss"]; present {
		iss, ok := issRaw.(string)
		if !ok {
			return nil, "", errors.New("iss is not a string")
		}
		if err := certchain.CheckIssuerName(leaf, iss); err != nil {
			return nil, "", err
		}
	}
	alg, err := sdjwtvcAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented certificate chain against an in-memory CertPool
// never touches the network.
func (r X5CIssuerKeyResolver) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
