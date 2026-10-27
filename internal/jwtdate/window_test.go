package jwtdate_test

import (
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
)

func TestWindowCheck(t *testing.T) {
	now := time.Unix(1700000000, 0)
	at := func(d time.Duration) int64 { return now.Add(d).Unix() }
	ptr := func(v int64) *int64 { return &v }
	for name, tc := range map[string]struct {
		window jwtdate.Window
		iat    int64
		exp    *int64
		nbf    *int64
		want   string
	}{
		"fresh":                  {jwtdate.Window{}, at(0), nil, nil, ""},
		"a little ahead":         {jwtdate.Window{}, at(30 * time.Second), nil, nil, ""},
		"old, with a future exp": {jwtdate.Window{}, at(-48 * time.Hour), ptr(at(time.Hour)), nil, ""},
		"within MaxAge":          {jwtdate.Window{MaxAge: time.Hour}, at(-30 * time.Minute), nil, nil, ""},
		"just before exp":        {jwtdate.Window{}, at(-time.Minute), ptr(at(time.Second)), nil, ""},
		"no iat":                 {jwtdate.Window{}, 0, nil, nil, "iat is missing"},
		"iat in the future":      {jwtdate.Window{}, at(time.Hour), nil, nil, "issued in the future"},
		"beyond a stated skew":   {jwtdate.Window{MaxClockSkew: time.Second}, at(10 * time.Second), nil, nil, "issued in the future"},
		"nbf in the future":      {jwtdate.Window{}, at(0), nil, ptr(at(time.Hour)), "isn't valid before"},
		"nbf out of range":       {jwtdate.Window{}, at(0), nil, ptr(-1), "nbf is out of range"},
		"older than MaxAge":      {jwtdate.Window{MaxAge: time.Hour}, at(-2 * time.Hour), nil, nil, "over the 1h0m0s allowed"},
		"old, no exp, no MaxAge": {jwtdate.Window{}, at(-48 * time.Hour), nil, nil, "over the 24h0m0s allowed"},
		"negative MaxAge":        {jwtdate.Window{MaxAge: -time.Second}, at(0), ptr(at(time.Hour)), nil, "MaxAge is negative"},
		"no exp, required":       {jwtdate.Window{RequireExp: true}, at(0), nil, nil, "missing the required exp"},
		"exp out of range":       {jwtdate.Window{}, at(0), ptr(jwtdate.Max + 1), nil, "exp is out of range"},
		"exp at iat":             {jwtdate.Window{}, at(0), ptr(at(0)), nil, "exp isn't after its iat"},
		"exp before iat":         {jwtdate.Window{}, at(30 * time.Second), ptr(at(10 * time.Second)), nil, "exp isn't after its iat"},
		// RFC 7519 §4.1.4: expired at exp, not after it.
		"at exp": {jwtdate.Window{}, at(-time.Minute), ptr(at(0)), nil, "is expired"},
	} {
		err := tc.window.Check(tc.iat, tc.exp, tc.nbf, now)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestFromCBOR(t *testing.T) {
	for _, v := range []any{uint64(jwtdate.Max + 1), int64(-1), float64(-1), float32(-1), "1700000000"} {
		if _, err := jwtdate.FromCBOR(v); err == nil {
			t.Errorf("FromCBOR(%T %v) accepted", v, v)
		}
	}
	for _, v := range []any{uint64(1700000000), int64(1700000000), 1700000000.5, float32(1 << 30)} {
		if _, err := jwtdate.FromCBOR(v); err != nil {
			t.Errorf("FromCBOR(%T %v): %v", v, v, err)
		}
	}
}
