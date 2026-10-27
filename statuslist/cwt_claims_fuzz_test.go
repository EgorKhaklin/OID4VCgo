package statuslist

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// FuzzParseCWTClaims fuzzes a CWT Status List Token's claims decoding
// and its status list's decompression directly: FuzzVerifyTokenCWT's
// inputs rarely get past the signature to reach them.
func FuzzParseCWTClaims(f *testing.F) {
	sl, err := New(Bits2, []uint8{0, 1, 2, 3}, "")
	if err != nil {
		f.Fatal(err)
	}
	cwtSL, err := toCWTStatusList(sl)
	if err != nil {
		f.Fatal(err)
	}
	seed, err := cbor.Marshal(map[int]any{cwtClaimSub: "https://example.com/statuslists/1", cwtClaimIat: 1767225600, cwtClaimExp: 1767229200, cwtClaimTTL: 300, cwtClaimStatusList: cwtSL})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		var decoded map[int]interface{}
		if cwtDecMode.Unmarshal(raw, &decoded) != nil {
			return
		}
		claims, err := parseCWTClaims(decoded)
		if err != nil {
			return
		}
		if claims.Sub == "" || claims.TTL != nil && *claims.TTL <= 0 {
			t.Fatalf("accepted claims without sub, or a ttl that isn't positive: %+v", claims)
		}
		if !claims.StatusList.Bits.valid() {
			return
		}
		for _, idx := range []int{0, 1, 1 << 20} {
			_, _ = claims.StatusList.Status(idx)
		}
	})
}
