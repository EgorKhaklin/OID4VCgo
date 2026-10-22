package mdoc

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
)

// The decoder an untrusted mdoc goes through is bounded: an array or
// map past MaxCBORContainerItems, nesting past MaxCBORNestedLevels, and
// a duplicate map key are refused before anything is built from them.
func TestDecoderBounds(t *testing.T) {
	encode := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	empties := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{}
		}
		return out
	}
	var nested any = 1
	for range MaxCBORNestedLevels + 1 {
		nested = []any{nested}
	}
	var v any
	if err := decMode.Unmarshal(encode(empties(MaxCBORContainerItems)), &v); err != nil {
		t.Errorf("an array at the bound: %v", err)
	}
	for name, data := range map[string][]byte{
		"array past the bound": encode(empties(MaxCBORContainerItems + 1)),
		"nested too deep":      encode(nested),
		// {"a": 1, "a": 2}
		"duplicate key": {0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
	} {
		if err := decMode.Unmarshal(data, &v); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// Each IssuerSignedItemBytes keeps within strictcbor's per-message item
// bound, but an IssuerSigned's items share one budget: sixteen
// elementValues of [[{} × 4096] × 15], 61 459 items each and a million
// in 1 MB, would otherwise each decode into interface{}.
func TestUnmarshalIssuerSigned_ItemBudget(t *testing.T) {
	value := []byte{0x8f}
	for range 15 {
		value = append(value, 0x99, 0x10, 0x00)
		value = append(value, bytes.Repeat([]byte{0xa0}, 4096)...)
	}
	wrapped, err := wrapTag24(map[string]cbor.RawMessage{
		"digestID":          {0x00},
		"random":            append([]byte{0x50}, make([]byte, 16)...),
		"elementIdentifier": {0x61, 'a'},
		"elementValue":      value,
	})
	if err != nil {
		t.Fatal(err)
	}
	items := make([]cbor.RawMessage, 16)
	for i := range items {
		items[i] = wrapped
	}
	data, err := encMode.Marshal(map[string]any{
		"nameSpaces": map[string]any{"ns": items},
		"issuerAuth": cbor.RawMessage{0x80},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalIssuerSigned(data); err == nil {
		t.Fatal("UnmarshalIssuerSigned = nil error, want the item budget spent")
	}
	// Decoding all sixteen made about a million allocations; the budget
	// stops at the second.
	allocs := testing.AllocsPerRun(1, func() { _, _ = UnmarshalIssuerSigned(data) })
	if allocs > 2*strictcbor.DefaultMaxItems {
		t.Errorf("UnmarshalIssuerSigned made %v allocations, want under %d", allocs, 2*strictcbor.DefaultMaxItems)
	}
}
