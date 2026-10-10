package jwtdate_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
)

func TestFromFloatAndUnix(t *testing.T) {
	for _, v := range []float64{-1, jwtdate.Max + 1, 1e15, 1e19, float64(math.MaxInt64), math.Inf(1), math.NaN()} {
		if _, err := jwtdate.FromFloat(v); !errors.Is(err, jwtdate.ErrOutOfRange) {
			t.Errorf("FromFloat(%v) = %v, want ErrOutOfRange", v, err)
		}
	}
	for _, v := range []int64{-1, jwtdate.Max + 1, math.MaxInt64 - 10, math.MinInt64} {
		if _, err := jwtdate.FromUnix(v); !errors.Is(err, jwtdate.ErrOutOfRange) {
			t.Errorf("FromUnix(%d) = %v, want ErrOutOfRange", v, err)
		}
	}
	if got, err := jwtdate.FromFloat(1700000000.9); err != nil || !got.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("FromFloat(1700000000.9) = %v, %v", got, err)
	}
	if got, err := jwtdate.FromUnix(jwtdate.Max); err != nil || got.UTC().Year() != 9999 {
		t.Errorf("FromUnix(Max) = %v, %v", got, err)
	}
}
