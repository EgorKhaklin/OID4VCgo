// Package certchain implements the one certificate-chain-trust
// primitive shared by every X5C/X5C-chain-shaped resolver this repo
// ships (verifier.X5CIssuerKeyResolver, verifier.X5ChainIssuerKeyResolver,
// issuer.X5CAttestationVerifier, issuer.X5CProofBindingKeyResolver):
// parse a leaf-first chain and verify it against a trust anchor set,
// rejecting a self-signed leaf even when that leaf is itself a
// configured root. Promoted here once a second package (issuer)
// needed the identical logic verifier already had — see
// ARCHITECTURE.md's own stance on not sharing code across a boundary
// until a second real consumer exists.
package certchain

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// X5CDERsFromHeader extracts header's own "x5c" member (RFC 7515
// §4.1.6: a JSON array of standard-base64-encoded DER certificates,
// leaf first) as raw DER bytes, requiring at least one entry —
// promoted here (from a private copy verifier once kept to itself)
// once wallet needed the identical logic to check a held credential's
// own issuer chain against a Credential Query's own TrustedAuthorities
// — see ARCHITECTURE.md's own stance on not sharing code across a
// boundary until a second real consumer exists, the same reason
// VerifyLeaf/DERsFromBase64 already live here rather than in one role
// package.
func X5CDERsFromHeader(header map[string]any) ([][]byte, error) {
	raw, ok := header["x5c"]
	if !ok {
		return nil, fmt.Errorf("certchain: header has no x5c member")
	}
	entries, ok := raw.([]any)
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("certchain: x5c header is not a non-empty array")
	}
	return DERsFromBase64(entries)
}

// VerifyLeaf parses ders (leaf first, then any intermediates — RFC
// 7515 §4.1.6's own "x5c" ordering, which RFC 9360 §2's own "x5chain"
// mirrors) and verifies the leaf against roots, rejecting a
// self-signed leaf even when that leaf is itself a configured root —
// HAIP's own trust model wants a leaf issued by a separate CA (so the
// leaf can be rotated/revoked without redistributing a new trust
// anchor to every relying party), not a leaf that doubles as its own
// anchor.
func VerifyLeaf(ders [][]byte, roots *x509.CertPool) (*x509.Certificate, error) {
	leaf, _, err := VerifyChains(ders, roots)
	return leaf, err
}

// VerifyLeafWithPolicy is VerifyLeaf, then policy (if non-nil) on the
// verified leaf and its verified paths — the role-specific check
// (extended key usage, certificate policy, issuer) chain validation
// alone doesn't make, since it accepts any key usage.
func VerifyLeafWithPolicy(ders [][]byte, roots *x509.CertPool, policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error) (*x509.Certificate, error) {
	leaf, chains, err := VerifyChains(ders, roots)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		if err := policy(leaf, chains); err != nil {
			return nil, fmt.Errorf("certchain: leaf certificate policy: %w", err)
		}
	}
	return leaf, nil
}

// VerifyChains is VerifyLeaf, also returning every verified path from
// the leaf to a certificate in roots (leaf first, root last), as
// crypto/x509's own Verify builds them. What a verified path says
// about who issued what can be relied on; what a certificate merely
// states about its own issuer (its Authority Key Identifier extension)
// can't — chain building doesn't require it to match.
//
// roots must be set: crypto/x509 treats a nil pool as "the system's
// roots", which would trust any publicly trusted certificate. A leaf
// that's itself a CA certificate is refused too: every role here signs
// with an end-entity certificate.
func VerifyChains(ders [][]byte, roots *x509.CertPool) (*x509.Certificate, [][]*x509.Certificate, error) {
	return VerifyChainsAt(ders, roots, time.Time{})
}

// VerifyChainsAt is VerifyChains, checking every certificate's validity
// period at now instead of the current time — for a caller whose own
// API takes an explicit verification time (proximity's reader). A zero
// now means the current time.
func VerifyChainsAt(ders [][]byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, [][]*x509.Certificate, error) {
	if roots == nil {
		return nil, nil, fmt.Errorf("certchain: no trust anchors configured (a nil root pool would mean the system roots)")
	}
	if len(ders) == 0 {
		return nil, nil, fmt.Errorf("certchain: certificate chain is empty")
	}
	certs := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("certchain: parse certificate chain entry %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	if IsSelfSigned(leaf) {
		return nil, nil, fmt.Errorf("certchain: leaf certificate must not be self-signed")
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return nil, nil, fmt.Errorf("certchain: leaf certificate must not be a CA certificate")
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("certchain: certificate chain does not verify against a trusted root: %w", err)
	}
	return leaf, chains, nil
}

// IsSelfSigned reports whether cert's own signature was produced by
// its own public key (regardless of any IsCA/BasicConstraints
// extension) — deliberately not x509.Certificate.CheckSignatureFrom,
// which additionally enforces CA constraints that a self-signed *leaf*
// (the exact shape VerifyLeaf rejects) typically doesn't carry.
func IsSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// DERsFromBase64 decodes entries (RFC 7515 §4.1.6: a JSON array of
// standard-base64-encoded DER certificates, leaf first, e.g. a JOSE
// "x5c" header member already type-asserted to []any) into raw DER
// bytes suitable for VerifyLeaf.
func DERsFromBase64(entries []any) ([][]byte, error) {
	ders := make([][]byte, 0, len(entries))
	for i, e := range entries {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("certchain: entry %d is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("certchain: decode entry %d: %w", i, err)
		}
		ders = append(ders, der)
	}
	return ders, nil
}

// CheckPresentedChain checks a certificate chain a signer presents in
// x5c or x5chain, leaf first, as HAIP 1.0 requires it (§4.1, §5,
// §6.1.1): the leaf isn't self-signed, each intermediate signs the
// certificate before it, and the trust anchor isn't included (a
// self-signed intermediate is one). A verifier then builds the path to
// its own anchors.
func CheckPresentedChain(leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	if leaf == nil {
		return errors.New("certchain: no leaf certificate")
	}
	if IsSelfSigned(leaf) {
		return errors.New("certchain: the leaf certificate is self-signed; it must be issued by a CA")
	}
	child := leaf
	for i, parent := range intermediates {
		if parent == nil {
			return fmt.Errorf("certchain: intermediate %d is nil", i)
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("certchain: intermediate %d didn't sign the certificate before it: %w", i, err)
		}
		if IsSelfSigned(parent) {
			return fmt.Errorf("certchain: intermediate %d is self-signed: leave the trust anchor out of the chain", i)
		}
		child = parent
	}
	return nil
}

// CheckIssuerName checks that iss, an SD-JWT VC's issuer claim, names
// the end-entity certificate leaf its key came from (SD-JWT VC, the
// x5c header): a "dns:" URI's DNS name must be one of leaf's dNSName
// subject alternative names, and any other iss one of its
// uniformResourceIdentifier names, compared exactly. A certificate a
// trusted root issued to another issuer can then sign nothing in this
// issuer's name, nor can one that shares only its host.
func CheckIssuerName(leaf *x509.Certificate, iss string) error {
	if strings.HasPrefix(iss, "dns:") {
		name := strings.TrimPrefix(strings.TrimPrefix(iss, "dns:"), "//")
		if name != "" && slices.ContainsFunc(leaf.DNSNames, func(d string) bool { return strings.EqualFold(d, name) }) {
			return nil
		}
		return fmt.Errorf("certchain: iss %q isn't a DNS name of the signing certificate", iss)
	}
	if iss != "" && slices.ContainsFunc(leaf.URIs, func(u *url.URL) bool { return u.String() == iss }) {
		return nil
	}
	return fmt.Errorf("certchain: iss %q isn't a URI of the signing certificate", iss)
}
