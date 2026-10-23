package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// AttestationStatusChecker checks a verified key attestation's
// revocation status (see Dependencies.AttestationStatus).
// a.Claims.Status is its "status" claim, nil when it has none; a Token
// Status List reference in it parses with statuslist.ParseStatusClaim,
// and the list fetched from its uri checks with statuslist.Checker (or
// statuslist.CheckX5C). Whether an attestation without a status claim
// is acceptable is the implementation's decision.
//
// Bind the Status List Token's signer to the attestation's: under
// roots shared by several Wallet Providers, any of them could otherwise
// sign a list that decides another's attestation's status. Set the
// checker's Options.IssuerKey to a.SignerKey, so a list signed with the
// attestation's own key is accepted, and Options.Issuer to
// a.Claims.Issuer, when it has one, so a list whose signer's
// certificate names that issuer is too — as verifier.RequireValidStatus
// does for a credential's status list.
type AttestationStatusChecker interface {
	CheckAttestationStatus(ctx context.Context, a VerifiedKeyAttestation) error
}

// VerifiedKeyAttestation is a key attestation whose signature verified,
// as AttestationStatusChecker sees it.
type VerifiedKeyAttestation struct {
	// Claims are its verified claims.
	Claims attestation.VerifiedClaims

	// SignerKey is the key its signature verified with: the one
	// Dependencies.AttestationVerifier resolved.
	SignerKey crypto.PublicKey

	// SignerCertificates is its x5c header's certificate chain, leaf
	// first, when it has one whose leaf holds SignerKey; nil otherwise.
	// X5CAttestationVerifier has verified it to its Roots; another
	// AttestationVerifier may not have looked at it.
	SignerCertificates []*x509.Certificate
}

// signerCertificates is a's x5c chain, leaf first, if its leaf holds
// signer; nil if it has none, or another.
func signerCertificates(a attestation.KeyAttestation, signer crypto.PublicKey) []*x509.Certificate {
	x5c := a.X5C()
	if len(x5c) == 0 {
		return nil
	}
	entries := make([]any, len(x5c))
	for i, s := range x5c {
		entries[i] = s
	}
	ders, err := certchain.DERsFromBase64(entries)
	if err != nil {
		return nil
	}
	certs := make([]*x509.Certificate, len(ders))
	for i, der := range ders {
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil
		}
	}
	if !certchain.SameKey(certs[0].PublicKey, signer) {
		return nil
	}
	return certs
}

// X5CAttestationVerifier implements AttestationVerifier by validating
// a presented Key Attestation JWT's own "x5c" header (RFC 7515
// §4.1.6) against Roots — a reference implementation of the one
// concrete trust strategy this package's own doc comments describe
// ("an x5c chain's own trust anchor"), the issuer-side analog of
// verifier.X5CIssuerKeyResolver/X5ChainIssuerKeyResolver. A self-signed
// leaf is always rejected, even if that exact certificate is itself a
// configured root — see internal/certchain.VerifyLeaf's own doc
// comment for why. A caller whose Key Attestation trust model is DID
// resolution, a private key registry, or OpenID Federation's own
// "trust_chain" (KeyAttestation.TrustChain) needs its own
// AttestationVerifier implementation instead — see that interface's
// own doc comment.
type X5CAttestationVerifier struct {
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

// ResolveAttestationKey implements AttestationVerifier.
func (v X5CAttestationVerifier) ResolveAttestationKey(ctx context.Context, a attestation.KeyAttestation) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	x5c := a.X5C()
	entries := make([]any, len(x5c))
	for i, s := range x5c {
		entries[i] = s
	}
	leaf, err := resolveX5CLeaf(ctx, entries, v.Roots, v.LeafPolicy)
	if err != nil {
		return nil, "", err
	}
	alg, err := algForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented x5c chain against an in-memory Roots pool never
// touches the network, so LiveFetchHardened is unconditionally true.
func (v X5CAttestationVerifier) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}

// algForKey maps pub to the JOSE algorithm this package's own signers
// use for it — the same ES256/EdDSA-only mapping
// verifier.sdjwtvcAlgForKey establishes on the verifying side, kept as
// its own small copy here rather than a cross-package export: it's a
// trivial, self-contained switch, not the security-relevant logic
// internal/certchain centralizes.
func algForKey(pub crypto.PublicKey) (jose.Alg, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return jose.ES256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("issuer: unsupported public key type %T", pub)
	}
}
