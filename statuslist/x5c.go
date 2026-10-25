package statuslist

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// IssueTokenX5C is IssueToken with the signer's certificate chain in the
// token's "x5c" header instead of a "kid": HAIP 1.0 §6.1 requires the key that
// validates a Status List Token to be in its x5c header, and the trust
// anchor's certificate not to be. chain is the signer's certificate
// first, then any intermediates — not the trust anchor.
func IssueTokenX5C(signer crypto.Signer, alg oid4vci.JOSEAlg, claims TokenClaims, chain []*x509.Certificate) (string, error) {
	ders, err := signerChain(signer, chain)
	if err != nil {
		return "", err
	}
	x5c := make([]string, len(ders))
	for i, der := range ders {
		x5c[i] = base64.StdEncoding.EncodeToString(der)
	}
	return issueToken(signer, alg, claims, map[string]any{"typ": TokenTyp, "x5c": x5c})
}

// IssueTokenCWTX5Chain is IssueTokenCWT with the signer's certificate
// chain in the token's protected "x5chain" header (RFC 9360) instead of
// a "kid" — the CWT counterpart to IssueTokenX5C.
func IssueTokenCWTX5Chain(signer crypto.Signer, alg oid4vci.COSEAlg, claims TokenClaims, chain []*x509.Certificate) ([]byte, error) {
	ders, err := signerChain(signer, chain)
	if err != nil {
		return nil, err
	}
	return issueTokenCWT(signer, alg, claims, cose.Headers{Typ: CWTTokenMediaType, X5Chain: ders})
}

// signerChain checks chain is non-empty and starts with signer's own
// certificate, returning its DER encodings.
func signerChain(signer crypto.Signer, chain []*x509.Certificate) ([][]byte, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("statuslist: a certificate chain is required")
	}
	pub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return nil, fmt.Errorf("statuslist: the chain's first certificate isn't the signer's")
	}
	// HAIP 1.0 §6.1: the signing certificate "MUST NOT be self-signed",
	// and the trust anchor "MUST NOT be included in the x5c" of the
	// token; each certificate must sign the one before it.
	if err := certchain.CheckPresentedChain(chain[0], chain[1:]); err != nil {
		return nil, fmt.Errorf("statuslist: %w", err)
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return ders, nil
}

// CheckX5C is Check for a Status List Token that carries its signer's
// certificate chain in its x5c header (IssueTokenX5C, HAIP 1.0): the
// chain must verify to one of roots, and its leaf must not be
// self-signed; the leaf's key then validates the token.
func CheckX5C(token string, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	return failClosed(checkX5C(context.Background(), token, roots, ref, opts))
}

// checkX5C is CheckX5C, before failClosed, with ctx for opts.Revocation.
func checkX5C(ctx context.Context, token string, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	header, _, err := jose.DecodeUnverifiedMax(token, maxTokenBytes)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: decode token: %w", err)
	}
	chain, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	leaf, err := verifySigner(ctx, chain, roots, opts)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	if err := checkSignerIsIssuer(leaf, opts); err != nil {
		return 0, TokenClaims{}, err
	}
	var alg jose.Alg
	switch leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		alg = jose.ES256
	case ed25519.PublicKey:
		alg = jose.EdDSA
	default:
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: unsupported key type %T", leaf.PublicKey)
	}
	return Check(token, leaf.PublicKey, alg, ref, opts)
}

// CheckCWTX5Chain is CheckX5C for a Status List Token in CWT format
// carrying its signer's certificate chain in an x5chain header
// (IssueTokenCWTX5Chain) — protected or, as RFC 9360 allows,
// unprotected; tagged or untagged.
func CheckCWTX5Chain(token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	return failClosed(checkCWTX5Chain(context.Background(), token, roots, ref, opts))
}

// checkCWTX5Chain is CheckCWTX5Chain, before failClosed, with ctx for
// opts.Revocation.
func checkCWTX5Chain(ctx context.Context, token []byte, roots *x509.CertPool, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	protected, unprotected, _, err := cose.DecodeUnverifiedMax(token, maxTokenBytes)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: decode token: %w", err)
	}
	chain := protected.X5Chain
	if len(chain) == 0 {
		chain = unprotected.X5Chain
	}
	leaf, err := verifySigner(ctx, chain, roots, opts)
	if err != nil {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: %w", err)
	}
	var alg cose.Alg
	switch leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		alg = cose.ES256
	case ed25519.PublicKey:
		alg = cose.EdDSA
	default:
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token signer: unsupported key type %T", leaf.PublicKey)
	}
	// As for a JWT token: Issuer and IssuerKey bind the signer.
	if err := checkSignerIsIssuer(leaf, opts); err != nil {
		return 0, TokenClaims{}, err
	}
	return CheckCWT(token, leaf.PublicKey, alg, ref, opts)
}

// verifySigner verifies a token signer's certificate chain to roots,
// on a path opts.LeafPolicy approves and opts.Revocation passes, and
// returns its leaf.
func verifySigner(ctx context.Context, chain [][]byte, roots *x509.CertPool, opts VerifyOptions) (*x509.Certificate, error) {
	leaf, _, err := certchain.VerifyTrustedChainsAt(ctx, chain, roots, opts.LeafPolicy, opts.Revocation, opts.certificateTime())
	return leaf, err
}

// certificateTime is when a token signer's certificates must be valid:
// Now, which the token's own times are checked against too, or the
// current time (zero) without it.
func (o VerifyOptions) certificateTime() time.Time {
	if o.Now == nil {
		return time.Time{}
	}
	return o.Now()
}

// checkSignerIsIssuer checks a JWT token's signer is the Referenced
// Token's issuer, as far as opts says who that is: it signs with
// IssuerKey, or its certificate names Issuer. With neither set the
// signer isn't bound beyond Roots.
func checkSignerIsIssuer(leaf *x509.Certificate, opts VerifyOptions) error {
	if (opts.Issuer == "" && opts.IssuerKey == nil) || certchain.SameKey(leaf.PublicKey, opts.IssuerKey) {
		return nil
	}
	if opts.Issuer == "" {
		return errors.New("statuslist: token signer isn't the referenced token's issuer: it signs with another key")
	}
	// The status of this issuer's tokens is its own to sign.
	if err := certchain.CheckIssuerName(leaf, opts.Issuer); err != nil {
		return fmt.Errorf("statuslist: token signer isn't the referenced token's issuer: neither its key nor a name its certificate carries: %w", err)
	}
	return nil
}
