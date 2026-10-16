package certchain

import (
	"context"
	"time"
)

type verificationTimeKey struct{}

// WithTime returns ctx carrying now, the instant a verification is made
// at, for every certificate check under it.
func WithTime(ctx context.Context, now time.Time) context.Context {
	return context.WithValue(ctx, verificationTimeKey{}, now)
}

// TimeFrom is the instant WithTime set on ctx, zero (the current time)
// when none was.
func TimeFrom(ctx context.Context) time.Time {
	t, _ := ctx.Value(verificationTimeKey{}).(time.Time)
	return t
}
