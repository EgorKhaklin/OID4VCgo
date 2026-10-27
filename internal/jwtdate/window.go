package jwtdate

import (
	"errors"
	"fmt"
	"time"
)

// DefaultMaxClockSkew is Window.MaxClockSkew's zero value's.
const DefaultMaxClockSkew = time.Minute

// DefaultMaxAgeWithoutExp bounds how long ago a token with no exp may
// have been issued, when Window.MaxAge is unset.
const DefaultMaxAgeWithoutExp = 24 * time.Hour

// Window is the freshness a status list token's times must meet.
type Window struct {
	// MaxAge, if set, refuses a token issued longer ago. Zero leaves
	// freshness to exp, and refuses a token without exp issued more
	// than DefaultMaxAgeWithoutExp ago. Negative is an error.
	MaxAge time.Duration

	// MaxClockSkew is how far in the future iat and nbf may be; zero
	// means DefaultMaxClockSkew.
	MaxClockSkew time.Duration

	// RequireExp refuses a token without exp.
	RequireExp bool
}

// Check checks a token's iat, exp and nbf at now: iat present (non-zero)
// and in range, iat and nbf no later than MaxClockSkew ahead (RFC 7519
// §4.1.5), iat no longer ago than MaxAge, exp after iat, and now before
// exp (RFC 7519 §4.1.4, RFC 8392 §3.1.4: "on or after" exp it is
// refused). Its errors carry no package prefix, for the caller to add
// its own.
func (w Window) Check(iat int64, exp, nbf *int64, now time.Time) error {
	if w.MaxAge < 0 {
		return errors.New("VerifyOptions.MaxAge is negative")
	}
	issued, err := FromUnix(iat)
	if err != nil || iat == 0 {
		return errors.New("token iat is missing or out of range")
	}
	skew := w.MaxClockSkew
	if skew == 0 {
		skew = DefaultMaxClockSkew
	}
	if issued.After(now.Add(skew)) {
		return errors.New("token was issued in the future")
	}
	if nbf != nil {
		notBefore, err := FromUnix(*nbf)
		if err != nil {
			return errors.New("token nbf is out of range")
		}
		if notBefore.After(now.Add(skew)) {
			return fmt.Errorf("token isn't valid before %s", notBefore.UTC().Format(time.RFC3339))
		}
	}
	return w.checkFreshness(issued, exp, now)
}

// checkFreshness checks a token issued at issued is no older than
// MaxAge allows and, with exp, unexpired at now.
func (w Window) checkFreshness(issued time.Time, exp *int64, now time.Time) error {
	if exp == nil && w.RequireExp {
		return errors.New("token is missing the required exp claim")
	}
	maxAge := w.MaxAge
	if maxAge == 0 && exp == nil {
		// Neither the token nor the caller bounds its freshness: a token
		// without exp would otherwise be good forever, so a copy cached
		// or replayed from before a revocation would keep saying valid.
		maxAge = DefaultMaxAgeWithoutExp
	}
	if maxAge > 0 && issued.Before(now.Add(-maxAge)) {
		return fmt.Errorf("token was issued %s ago, over the %s allowed", now.Sub(issued).Round(time.Second), maxAge)
	}
	if exp == nil {
		return nil
	}
	expires, err := FromUnix(*exp)
	if err != nil {
		return errors.New("token exp is out of range")
	}
	// A token that expires as it's issued was never valid; the issuers
	// in this module refuse to sign one.
	if !expires.After(issued) {
		return errors.New("token exp isn't after its iat")
	}
	if !now.Before(expires) {
		return errors.New("token is expired")
	}
	return nil
}
