package statuslist

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
)

// TokenTyp is the required JOSE "typ" header of a Status List Token in
// JWT format (draft-14 §5.1).
const TokenTyp = "statuslist+jwt" //nolint:gosec // a JOSE "typ" header value, not a credential

// TokenMediaType is the media type a Status List Token in JWT format
// is served and requested as (draft-14 §8.1, §8.2).
const TokenMediaType = "application/statuslist+jwt"

// TokenClaims is a Status List Token's JWT Claims Set (draft-14 §5.1).
type TokenClaims struct {
	Sub        string // REQUIRED: the URI this Status List Token is served at
	Iat        int64  // REQUIRED
	Exp        *int64
	TTL        *int64 // seconds
	StatusList StatusList

	Additional map[string]any
}

// IssueToken signs claims into a Status List Token in JWT format
// (draft-14 §5.1). keyID sets the JOSE "kid" header, if non-empty.
func IssueToken(signer crypto.Signer, alg oid4vci.JOSEAlg, claims TokenClaims, keyID string) (string, error) {
	header := map[string]any{"typ": TokenTyp}
	if keyID != "" {
		header["kid"] = keyID
	}
	return issueToken(signer, alg, claims, header)
}

// issueToken signs claims into a Status List Token in JWT format with
// the given JOSE header.
func issueToken(signer crypto.Signer, alg jose.Alg, claims TokenClaims, header map[string]any) (string, error) {
	if claims.Sub == "" {
		return "", fmt.Errorf("statuslist: TokenClaims.Sub is required")
	}
	if !claims.StatusList.Bits.valid() {
		return "", fmt.Errorf("statuslist: TokenClaims.StatusList.Bits is invalid")
	}

	payload := make(map[string]any, len(claims.Additional)+5)
	for k, v := range claims.Additional {
		payload[k] = v
	}
	payload["sub"] = claims.Sub
	payload["iat"] = claims.Iat
	if claims.Exp != nil {
		payload["exp"] = *claims.Exp
	}
	if claims.TTL != nil {
		payload["ttl"] = *claims.TTL
	}
	payload["status_list"] = claims.StatusList

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: marshal token claims: %w", err)
	}

	return jose.Sign(alg, signer, header, raw)
}

// VerifyOptions configures VerifyToken.
type VerifyOptions struct {
	Now func() time.Time // defaults to time.Now

	// MaxAge, if set, refuses a token issued longer ago (its iat): a
	// signed list from before a revocation stays valid until its exp,
	// or forever without one, so anyone who can serve bytes at the
	// status URI (a cache, a mirror) could replay it. Zero leaves
	// freshness to exp.
	MaxAge time.Duration

	// MaxClockSkew is how far in the future a token's iat may be;
	// zero means a minute.
	MaxClockSkew time.Duration

	// LeafPolicy, used by CheckX5C/CheckCWTX5Chain only, is run on the
	// token signer's chain-verified certificate and its verified paths,
	// and can refuse it. Chain validation accepts any certificate under
	// the roots, whatever its role, and nothing ties the status list's
	// signer to the Referenced Token's issuer: use it to require that
	// tie, or the signer's role (an extended key usage, a certificate
	// policy), where the roots are shared.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// Issuer, if set, is the Referenced Token's issuer: its iss, or
	// the URI its signing certificate names. CheckX5C then refuses a
	// Status List Token whose signer certificate doesn't name it (the
	// rule certchain.CheckIssuerName applies), so another issuer's
	// certificate under the same Roots can't sign this issuer's
	// status, and one whose own iss claim is another issuer's. For the
	// CWT form (an mdoc's), leave it empty: an mdoc issuer has no such
	// name, and its status lists are bound by Roots, which the MSO's
	// status reference can name.
	Issuer string
}

// maxTokenBytes is this package's own ceiling on the compact JWS
// jose.VerifyMax will parse, in place of jose.MaxCompactBytes's own
// smaller default — a Status List Token's payload embeds a
// population-sized compressed bit array (see bits.go's own
// maxDecompressedSize doc comment: even a 2^20-entry list decompresses
// to only 128 KiB, so its compressed, base64url-encoded form fits
// comfortably within this), and the token is fetched from a URI a
// credential names, which may point at a compromised or malicious
// issuer.
const maxTokenBytes = 1 << 20 // 1 MiB

// VerifyToken verifies a Status List Token's signature and typ header,
// and rejects an expired token (draft-14 §5.1 rule 2-3, §8.3 step 4c).
// It does not check sub against a specific Referenced Token — that's
// Check's job, since it needs the StatusListRef to compare against.
func VerifyToken(token string, pub crypto.PublicKey, alg oid4vci.JOSEAlg, opts VerifyOptions) (TokenClaims, error) {
	header, raw, err := jose.VerifyMax(alg, pub, token, maxTokenBytes)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: verify token signature: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != TokenTyp {
		return TokenClaims{}, fmt.Errorf("statuslist: token typ is %q, want %q", typ, TokenTyp)
	}

	var decoded struct {
		Iss        string     `json:"iss"`
		Sub        string     `json:"sub"`
		Iat        int64      `json:"iat"`
		Exp        *int64     `json:"exp"`
		TTL        *int64     `json:"ttl"`
		StatusList StatusList `json:"status_list"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: unmarshal token claims: %w", err)
	}
	if decoded.Sub == "" {
		return TokenClaims{}, fmt.Errorf("statuslist: token is missing the required sub claim")
	}
	if decoded.Iss != "" && opts.Issuer != "" && decoded.Iss != opts.Issuer {
		return TokenClaims{}, fmt.Errorf("statuslist: token iss %q isn't the referenced token's issuer %q", decoded.Iss, opts.Issuer)
	}
	if !decoded.StatusList.Bits.valid() {
		return TokenClaims{}, fmt.Errorf("statuslist: token's status_list.bits is invalid")
	}

	if err := checkTokenTimes(decoded.Iat, decoded.Exp, opts); err != nil {
		return TokenClaims{}, err
	}

	return TokenClaims{
		Sub:        decoded.Sub,
		Iat:        decoded.Iat,
		Exp:        decoded.Exp,
		TTL:        decoded.TTL,
		StatusList: decoded.StatusList,
	}, nil
}

// defaultMaxClockSkew is VerifyOptions.MaxClockSkew's zero value's.
const defaultMaxClockSkew = time.Minute

// checkTokenTimes checks a Status List Token's iat, which draft-14
// §5.1 requires, and exp, against opts: issued not in the future (past
// MaxClockSkew), not longer ago than MaxAge when it's set, and not
// expired.
func checkTokenTimes(iat int64, exp *int64, opts VerifyOptions) error {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	t := now()
	issued, err := jwtdate.FromUnix(iat)
	if err != nil || iat == 0 {
		return fmt.Errorf("statuslist: token iat is missing or out of range")
	}
	skew := opts.MaxClockSkew
	if skew == 0 {
		skew = defaultMaxClockSkew
	}
	if issued.After(t.Add(skew)) {
		return fmt.Errorf("statuslist: token was issued in the future")
	}
	if opts.MaxAge > 0 && issued.Before(t.Add(-opts.MaxAge)) {
		return fmt.Errorf("statuslist: token was issued %s ago, over the %s allowed", t.Sub(issued).Round(time.Second), opts.MaxAge)
	}
	if exp != nil {
		expires, err := jwtdate.FromUnix(*exp)
		if err != nil {
			return fmt.Errorf("statuslist: token exp is out of range")
		}
		if t.After(expires) {
			return fmt.Errorf("statuslist: token is expired")
		}
	}
	return nil
}
