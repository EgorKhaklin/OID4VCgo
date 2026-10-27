package strictcbor

import (
	"errors"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestWellformed_DuplicateAfterAscendingKeys(t *testing.T) {
	mode := testMode(t)
	// {1: 0, 2: {3: 0}, 4: 0, 2: 0}: the duplicate comes after three
	// keys in order, so the keys before it are read again.
	err := mode.Wellformed([]byte{0xa4, 0x01, 0x00, 0x02, 0xa1, 0x03, 0x00, 0x04, 0x00, 0x02, 0x00})
	var dup *cbor.DupMapKeyError
	if !errors.As(err, &dup) || dup.Index != 3 {
		t.Fatalf("Wellformed = %v, want a *cbor.DupMapKeyError at index 3", err)
	}
}

// canonicalMap is a deterministically encoded map of n distinct byte
// string keys of up to three bytes, each to an empty map.
func canonicalMap(n int) []byte {
	b := []byte{0xba, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	for i := range n {
		switch {
		case i < 1<<8:
			b = append(b, 0x41, byte(i), 0xa0)
		case i < 1<<16:
			b = append(b, 0x42, byte(i>>8), byte(i), 0xa0)
		default:
			b = append(b, 0x43, byte(i>>16), byte(i>>8), byte(i), 0xa0)
		}
	}
	return b
}

func bstrKeyMode(t testing.TB, n int) DecMode {
	return mustMode(t, cbor.DecOptions{MapKeyByteString: cbor.MapKeyByteStringAllowed, MaxMapPairs: n}).WithMaxItems(4 * n)
}

func TestWellformed_DeterministicMapKeepsNoKeys(t *testing.T) {
	const n = 200_000
	mode := bstrKeyMode(t, n)
	data := canonicalMap(n)
	allocs := testing.AllocsPerRun(3, func() {
		if err := mode.Wellformed(data); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 5 {
		t.Errorf("Wellformed of a %d-key deterministic map made %v allocations", n, allocs)
	}
	// Repeating the second-to-last key in the last puts the map out of
	// order: every key is then kept, and the duplicate found.
	dup := slices.Clone(data)
	copy(dup[len(dup)-4:], dup[len(dup)-8:len(dup)-4])
	if err := mode.Wellformed(dup); err == nil {
		t.Error("Wellformed of the map with a key repeated = nil error")
	}
}

func BenchmarkWellformed_DeterministicMap(b *testing.B) {
	const n = 800_000
	mode := bstrKeyMode(b, n)
	data := canonicalMap(n)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := mode.Wellformed(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWellformed_UnorderedMap(b *testing.B) {
	const n = 800_000
	mode := bstrKeyMode(b, n)
	data := canonicalMap(n)
	// Swap the first two entries (one-byte keys): out of order from
	// the second key on.
	copy(data[5:8], []byte{0x41, 0x01, 0xa0})
	copy(data[8:11], []byte{0x41, 0x00, 0xa0})
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if err := mode.Wellformed(data); err != nil {
			b.Fatal(err)
		}
	}
}
