package strictcbor

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func mustMode(t testing.TB, o cbor.DecOptions) DecMode {
	t.Helper()
	o.DupMapKey = cbor.DupMapKeyEnforcedAPF
	mode, err := o.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	return Wrap(mode)
}

func TestWellformed_Walk(t *testing.T) {
	mode := mustMode(t, cbor.DecOptions{MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16})
	tests := []struct {
		name string
		data []byte
		ok   bool
	}{
		{"int", []byte{0x01}, true},
		{"array", []byte{0x82, 0x01, 0x02}, true},
		{"map", []byte{0xa2, 0x01, 0x02, 0x03, 0x04}, true},
		{"dup at depth 3", []byte{0x81, 0x81, 0xa2, 0x01, 0x00, 0x01, 0x00}, false},
		{"dup text keys", []byte{0xa2, 0x61, 'a', 0x00, 0x61, 'a', 0x00}, false},
		{"dup non-shortest int", []byte{0xa2, 0x01, 0x00, 0x18, 0x01, 0x00}, false},
		{"dup indefinite text", []byte{0xa2, 0x62, 'a', 'b', 0x00, 0x7f, 0x61, 'a', 0x61, 'b', 0xff, 0x00}, false},
		{"dup half and double", []byte{0xa2, 0xf9, 0x3c, 0x00, 0x00, 0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0, 0x00}, false},
		{"dup zero and minus zero", []byte{0xa2, 0xf9, 0x00, 0x00, 0x00, 0xf9, 0x80, 0x00, 0x00}, false},
		{"dup null and undefined", []byte{0xa2, 0xf6, 0x00, 0xf7, 0x00}, false},
		{"dup self-described", []byte{0xa2, 0x01, 0x00, 0xd9, 0xd9, 0xf7, 0x01, 0x00}, false},
		{"dup tagged keys", []byte{0xa2, 0xc5, 0x01, 0x00, 0xc5, 0x01, 0x00}, false},
		{"dup after ascending keys", []byte{0xa4, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00}, false},
		{"descending keys", []byte{0xa3, 0x03, 0x00, 0x02, 0x00, 0x01, 0x00}, true},
		{"dup after nested maps", []byte{0xa3, 0x01, 0xa1, 0x02, 0x00, 0x03, 0xa0, 0x01, 0x00}, false},
		{"dup after indefinite values", []byte{0xa3, 0x01, 0x5f, 0x41, 0x00, 0xff, 0x02, 0x9f, 0xa0, 0xff, 0x01, 0x00}, false},
		{"dup after tagged key", []byte{0xa4, 0xc5, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00}, false},
		{"dup bytes out of order", []byte{0xa3, 0x42, 0x00, 0x00, 0x00, 0x41, 0x01, 0x00, 0x42, 0x00, 0x00, 0x00}, false},
		{"bytes in deterministic order", []byte{0xa2, 0x41, 0x01, 0x00, 0x42, 0x00, 0x00, 0x00}, true},
		{"indefinite map late dup", []byte{0xbf, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0xff}, false},
		{"NaN keys", []byte{0xa2, 0xf9, 0x7e, 0x00, 0x00, 0xf9, 0x7e, 0x00, 0x00}, true},
		{"int and text", []byte{0xa2, 0x01, 0x00, 0x61, 0x01, 0x00}, true},
		{"bytes and text", []byte{0xa2, 0x41, 'a', 0x00, 0x61, 'a', 0x00}, true},
		{"1 and -1", []byte{0xa2, 0x01, 0x00, 0x20, 0x00}, true},
		{"different tagged keys", []byte{0xa2, 0xc5, 0x01, 0x00, 0xc6, 0x01, 0x00}, true},
		{"array key", []byte{0xa1, 0x80, 0x00}, false},
		{"big negative key", []byte{0xa1, 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}, false},
		{"indefinite array", []byte{0x9f, 0x01, 0x02, 0xff}, true},
		{"indefinite map dup", []byte{0xbf, 0x01, 0x00, 0x01, 0x00, 0xff}, false},
		{"indefinite map odd", []byte{0xbf, 0x01, 0xff}, false},
		{"indefinite bytes", []byte{0x5f, 0x41, 0x00, 0x42, 0x01, 0x02, 0xff}, true},
		{"indefinite chunk wrong type", []byte{0x5f, 0x61, 'a', 0xff}, false},
		{"nested indefinite chunk", []byte{0x5f, 0x5f, 0xff, 0xff}, false},
		{"tag", []byte{0xd8, 0x18, 0x41, 0x00}, true},
		{"tdate", append([]byte{0xc0, 0x74}, "2026-01-01T00:00:00Z"...), true},
		{"bad tdate", []byte{0xc0, 0x61, 'x'}, false},
		{"tdate not text", []byte{0xc0, 0x01}, false},
		{"bignum not bytes", []byte{0xc2, 0x01}, false},
		{"invalid UTF-8", []byte{0x61, 0xff}, false},
		{"depth 4", []byte{0x81, 0x81, 0x81, 0x81, 0x01}, true},
		{"depth 5", []byte{0x81, 0x81, 0x81, 0x81, 0x81, 0x01}, false},
		{"nested tags count", []byte{0x81, 0x81, 0x81, 0xc5, 0xc5, 0x80}, false},
		{"array over cap", append([]byte{0x91}, make([]byte, 17)...), false},
		{"truncated", []byte{0x82, 0x01}, false},
		{"truncated length", []byte{0x5a, 0xff, 0xff, 0xff, 0xff}, false},
		{"huge array header", []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},
		{"reserved ai", []byte{0x1c}, false},
		{"bare break", []byte{0xff}, false},
		{"two-byte simple below 32", []byte{0xf8, 0x10}, false},
		{"extra data", []byte{0x01, 0x02}, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mode.Wellformed(tt.data)
			if (err == nil) != tt.ok {
				t.Errorf("Wellformed(%x) = %v, want ok %v", tt.data, err, tt.ok)
			}
			var item any
			want := mode.DecMode.Unmarshal(tt.data, &item)
			if (err == nil) != (want == nil) {
				t.Errorf("Wellformed(%x) = %v, decoding into any = %v", tt.data, err, want)
			}
		})
	}
}

func TestWellformed_DuplicateError(t *testing.T) {
	mode := testMode(t)
	var dup *cbor.DupMapKeyError
	if err := mode.Wellformed(dupInner); !errors.As(err, &dup) {
		t.Errorf("Wellformed = %v, want a *cbor.DupMapKeyError", err)
	}
}

// nested is {"x": [[{} × inner] × outer]}: every container within a
// cap of inner or outer elements, three levels deep.
func nested(outer, inner int) []byte {
	b := []byte{0xa1, 0x61, 'x', 0x99, byte(outer >> 8), byte(outer)}
	for range outer {
		b = append(b, 0x99, byte(inner>>8), byte(inner))
		b = append(b, bytes.Repeat([]byte{0xa0}, inner)...)
	}
	return b
}

func TestMaxItems(t *testing.T) {
	mode := testMode(t)
	// 4 + 15 × (1 + 4096) items.
	if err := mode.Wellformed(nested(15, 4096)); err != nil {
		t.Errorf("Wellformed(61 459 items) = %v", err)
	}
	if err := mode.Wellformed(nested(16, 4096)); err == nil {
		t.Error("Wellformed(65 556 items) = nil error, want over DefaultMaxItems")
	}
	var v struct{}
	if err := mode.Unmarshal(nested(250, 4096), &v); err == nil {
		t.Error("Unmarshal(a million maps) = nil error")
	}
	small := mode.WithMaxItems(4)
	if got := small.MaxItems(); got != 4 {
		t.Errorf("MaxItems = %d, want 4", got)
	}
	if err := small.Wellformed([]byte{0x83, 0x01, 0x02, 0x03}); err != nil {
		t.Errorf("Wellformed(4 items) = %v", err)
	}
	if err := small.Wellformed([]byte{0x84, 0x01, 0x02, 0x03, 0x04}); err == nil {
		t.Error("Wellformed(5 items) = nil error, want over 4")
	}
	var a []int
	if _, err := small.UnmarshalFirst([]byte{0x9f, 0x01, 0x02, 0x03, 0x04, 0xff}, &a); err == nil {
		t.Error("UnmarshalFirst(5 items) = nil error, want over 4")
	}
}

func TestWithBudget(t *testing.T) {
	mode := testMode(t).WithBudget(10)
	three := []byte{0x82, 0x01, 0x02}
	var v []int
	for i := range 3 {
		if err := mode.Unmarshal(three, &v); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// 9 of 10 spent, by this mode or a copy of it.
	copied := mode.WithMaxItems(100)
	if err := copied.Wellformed(three); err == nil {
		t.Error("Wellformed past the budget = nil error")
	}
	if err := testMode(t).Wellformed(three); err != nil {
		t.Errorf("a mode without the budget: %v", err)
	}
}

func TestMaxItems_RefusedBeforeDecoding(t *testing.T) {
	mode := testMode(t)
	data := nested(250, 4096)
	var v struct{}
	allocs := testing.AllocsPerRun(5, func() {
		_ = mode.Unmarshal(data, &v)
	})
	if allocs > 20 {
		t.Errorf("Unmarshal of a million maps made %v allocations, want it refused before decoding", allocs)
	}
}

func TestWrap_RefusesKeyChangingOptions(t *testing.T) {
	mode, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, DefaultByteStringType: reflect.TypeOf("")}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("Wrap didn't panic")
		}
	}()
	Wrap(mode)
}

// FuzzWellformed checks the walk against what it replaced: decoding the
// item into an empty interface with the same options, which refuses
// duplicate keys at every depth. Inputs this short are far under
// DefaultMaxItems.
func FuzzWellformed(f *testing.F) {
	for _, seed := range [][]byte{
		dupInner,
		{0xa2, 0x01, 0x00, 0x18, 0x01, 0x00},
		{0xa2, 0x62, 'a', 'b', 0x00, 0x7f, 0x61, 'a', 0x61, 'b', 0xff, 0x00},
		{0xa2, 0xf9, 0x3c, 0x00, 0x00, 0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0, 0x00},
		{0xa2, 0xf6, 0x00, 0xf7, 0x00},
		{0xa2, 0xc5, 0x01, 0x00, 0xc5, 0x01, 0x00},
		{0xbf, 0x01, 0x00, 0x01, 0x00, 0xff},
		{0xd8, 0x18, 0x41, 0x00},
		{0xc1, 0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0},
		{0xa1, 0xd9, 0xd9, 0xf7, 0xc0, 0x61, 'x', 0x00},
		{0x81, 0x81, 0x81, 0xc5, 0xc5, 0x80},
	} {
		f.Add(seed)
	}
	modes := []DecMode{
		mustMode(f, cbor.DecOptions{}),
		mustMode(f, cbor.DecOptions{MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16, TimeTag: cbor.DecTagRequired}),
		mustMode(f, cbor.DecOptions{IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden}),
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for i, mode := range modes {
			got := mode.Wellformed(data)
			var item any
			want := mode.DecMode.Unmarshal(data, &item)
			if (got == nil) != (want == nil) {
				t.Fatalf("mode %d: Wellformed(%x) = %v, decoding into any = %v", i, data, got, want)
			}
			if got == nil {
				var v any
				if err := mode.Unmarshal(data, &v); err != nil {
					t.Fatalf("mode %d: Unmarshal(%x) = %v after Wellformed passed", i, data, err)
				}
			}
		}
	})
}
