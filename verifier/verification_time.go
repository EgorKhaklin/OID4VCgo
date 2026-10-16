package verifier

import (
	"context"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// WithVerificationTime returns ctx carrying now, the instant a
// verification is made at: X5CIssuerKeyResolver and
// X5ChainIssuerKeyResolver, and dcql.AKITrustedAuthoritiesChecker,
// then check certificates' validity at it, as
// the rest of the verification checks expiry and ages at
// VerifyResponseRequest.Now. VerifyResponse sets it from its request's
// Now; a caller of a resolver directly, or of mdocdcapi.VerifyResponse,
// sets it the same way.
func WithVerificationTime(ctx context.Context, now time.Time) context.Context {
	return certchain.WithTime(ctx, now)
}

// verificationTime is the instant WithVerificationTime set on ctx, zero
// (the current time) when none was.
func verificationTime(ctx context.Context) time.Time {
	return certchain.TimeFrom(ctx)
}
