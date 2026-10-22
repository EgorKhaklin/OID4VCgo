package strictcbor

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func testMode(t *testing.T) DecMode {
	t.Helper()
	mode, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		t.Fatal(err)
	}
	return Wrap(mode)
}

// {1: {2: 3, 2: 4}}
var dupInner = []byte{0xa1, 0x01, 0xa2, 0x02, 0x03, 0x02, 0x04}

func TestUnmarshal_RefusesDuplicateInsideRawMessage(t *testing.T) {
	mode := testMode(t)
	var plain map[int]cbor.RawMessage
	if err := mode.DecMode.Unmarshal(dupInner, &plain); err != nil {
		t.Fatalf("unwrapped Unmarshal = %v, want nil (the gap this package closes)", err)
	}
	var v map[int]cbor.RawMessage
	if err := mode.Unmarshal(dupInner, &v); err == nil {
		t.Error("Unmarshal = nil error, want a duplicate map key error")
	}
}

func TestUnmarshalFirst_RefusesDuplicateInsideRawMessage(t *testing.T) {
	mode := testMode(t)
	var v map[int]cbor.RawMessage
	if _, err := mode.UnmarshalFirst(append(dupInner, 0x01), &v); err == nil {
		t.Error("UnmarshalFirst = nil error, want a duplicate map key error")
	}
}

func TestUnmarshalFirst_ReturnsRest(t *testing.T) {
	mode := testMode(t)
	var v int
	rest, err := mode.UnmarshalFirst([]byte{0x01, 0x02}, &v)
	if err != nil || v != 1 || len(rest) != 1 || rest[0] != 0x02 {
		t.Errorf("UnmarshalFirst = %d, %x, %v; want 1, 02, nil", v, rest, err)
	}
}

func TestWellformed_RefusesDuplicate(t *testing.T) {
	mode := testMode(t)
	if err := mode.DecMode.Wellformed(dupInner); err != nil {
		t.Fatalf("unwrapped Wellformed = %v, want nil", err)
	}
	if err := mode.Wellformed(dupInner); err == nil {
		t.Error("Wellformed = nil error, want a duplicate map key error")
	}
	if err := mode.Wellformed([]byte{0xa1, 0x01, 0x02}); err != nil {
		t.Errorf("Wellformed({1: 2}) = %v, want nil", err)
	}
}

func TestUnmarshal_Decodes(t *testing.T) {
	mode := testMode(t)
	var v map[int]cbor.RawMessage
	if err := mode.Unmarshal([]byte{0xa1, 0x01, 0xa1, 0x02, 0x03}, &v); err != nil {
		t.Fatal(err)
	}
	if got := v[1]; len(got) != 3 {
		t.Errorf("v[1] = %x, want a1 02 03", got)
	}
}
