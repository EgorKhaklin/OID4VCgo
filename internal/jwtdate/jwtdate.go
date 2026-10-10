// Package jwtdate converts JWT NumericDates (RFC 7519 §2) to times,
// refusing the values time.Unix and Duration arithmetic can't hold: a
// date near int64's maximum wraps into the far past, and the age of one
// far in the future saturates, so an iat or nbf there would pass a
// freshness check.
package jwtdate

import (
	"errors"
	"math"
	"time"
)

// Max is the latest NumericDate accepted: 9999-12-31T23:59:59Z.
const Max = 253402300799

// ErrOutOfRange is returned for a NumericDate before 1970 or after Max,
// or not a finite number.
var ErrOutOfRange = errors.New("jwtdate: NumericDate out of range")

// FromUnix is the time sec seconds after 1970, in range.
func FromUnix(sec int64) (time.Time, error) {
	if sec < 0 || sec > Max {
		return time.Time{}, ErrOutOfRange
	}
	return time.Unix(sec, 0), nil
}

// FromFloat is FromUnix for a JSON number, its fraction dropped.
func FromFloat(v float64) (time.Time, error) {
	if math.IsNaN(v) || v < 0 || v > Max {
		return time.Time{}, ErrOutOfRange
	}
	return time.Unix(int64(v), 0), nil
}
