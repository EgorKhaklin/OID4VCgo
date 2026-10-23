package mdoc_test

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// RoundedValidity gives every mdoc issued on one UTC day the same
// signed/validFrom (that day's start) and validUntil (plus lifetime),
// whatever time zone now is in.
func TestRoundedValidity(t *testing.T) {
	const lifetime = 30 * 24 * time.Hour
	dayStart := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	tokyo := time.FixedZone("JST", 9*60*60)
	for _, now := range []time.Time{
		dayStart,
		dayStart.Add(13*time.Hour + 7*time.Minute + 5*time.Second + 123),
		dayStart.Add(24*time.Hour - time.Nanosecond),
		dayStart.Add(20 * time.Hour).In(tokyo), // 2026-10-24 05:00 in Tokyo
	} {
		signed, validFrom, validUntil := mdoc.RoundedValidity(now, lifetime)
		if !signed.Equal(dayStart) || !validFrom.Equal(dayStart) || !validUntil.Equal(dayStart.Add(lifetime)) {
			t.Errorf("RoundedValidity(%v) = %v, %v, %v; want %v, %v, %v", now, signed, validFrom, validUntil, dayStart, dayStart, dayStart.Add(lifetime))
		}
		if signed.Location() != time.UTC {
			t.Errorf("RoundedValidity(%v): signed in %v, want UTC", now, signed.Location())
		}
	}
	if signed, _, _ := mdoc.RoundedValidity(dayStart.Add(24*time.Hour), lifetime); !signed.Equal(dayStart.Add(24 * time.Hour)) {
		t.Errorf("the next day's signed = %v, want %v", signed, dayStart.Add(24*time.Hour))
	}
}
