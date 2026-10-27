package identifierlist

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Checker checks an MSO's identifier list reference end to end: it
// fetches the list at ref.URI, then Checks it. Fetcher is
// statuslist.Fetcher, with its https-only, redirect, content type,
// size and public-address rules; a zero MaxBytes means this package's
// own 4 MiB. The list must be served as MediaType.
//
// A Checker holds nothing about any one credential, so one serves
// every credential: each Check is given the MSO's reference and its
// document signer path, and binds the list's signer to that mdoc's
// issuer (ISO/IEC 18013-5 §12.3.6.2) itself.
//
// A Checker caches nothing: each Check fetches the list and verifies
// it again, and a list near the 4 MiB limit takes a noticeable fraction
// of a second to verify. A token's ttl (TokenClaims.TTL) only says how
// long a Relying Party may cache it, and nothing here acts on it. A
// caller checking many MSOs against one list can cache what Check
// returns, keyed by the reference's uri and Certificate and the CA that
// signed the document signer (what binds the list's signer), for no
// longer than the token's ttl and exp allow, and test each further
// MSO's id with TokenClaims.Contains.
type Checker struct {
	Fetcher statuslist.Fetcher

	// Roots are the trust anchors for list signers when the reference
	// names no Certificate: normally the IACA certificates the mdoc
	// issuers chain to. A signer must also be under the CA that signed
	// the mdoc's document signer, not just under any of them: Check
	// refuses a reference with no Certificate given no document signer
	// path, unless Options.UnboundSigner decides the signer.
	Roots *x509.CertPool

	Options VerifyOptions
}

// Check validates ref, fetches the list it names and checks it, as
// Check does: documentSignerPath is the MSO's IssuerAuth x5chain as
// verified, and ref and it must come from a verified MSO. With an
// error, revoked is true.
func (c Checker) Check(ctx context.Context, ref Ref, documentSignerPath []*x509.Certificate) (revoked bool, claims TokenClaims, err error) {
	if err := ref.validate(); err != nil {
		return true, TokenClaims{}, err
	}
	f := c.Fetcher
	if f.MaxBytes <= 0 {
		f.MaxBytes = maxTokenBytes
	}
	token, err := f.Fetch(ctx, ref.URI, MediaType)
	if err != nil {
		return true, TokenClaims{}, fmt.Errorf("identifierlist: %w", err)
	}
	return Check(ctx, token, c.Roots, ref, documentSignerPath, c.Options)
}

// ErrRevoked is RequireNotRevoked's error for an MSO on its list.
var ErrRevoked = errors.New("identifierlist: the MSO's identifier is on its identifier list: it is revoked")

// RequireNotRevoked checks ref as Check does, and returns nil only when
// the MSO isn't revoked: ErrRevoked when it is, and Check's error when
// the list can't be read.
func (c Checker) RequireNotRevoked(ctx context.Context, ref Ref, documentSignerPath []*x509.Certificate) error {
	revoked, _, err := c.Check(ctx, ref, documentSignerPath)
	if err != nil {
		return err
	}
	if revoked {
		return ErrRevoked
	}
	return nil
}
