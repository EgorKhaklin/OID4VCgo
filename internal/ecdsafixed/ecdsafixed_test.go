package ecdsafixed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := key.Sign(rand.Reader, []byte("digest-sized-input-000000000000"), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	fixed, err := ToFixed(der, 32)
	if err != nil {
		t.Fatalf("ToFixed: %v", err)
	}
	if len(fixed) != 64 {
		t.Fatalf("len(fixed) = %d, want 64", len(fixed))
	}

	roundTripped, err := ToDER(fixed, 32)
	if err != nil {
		t.Fatalf("ToDER: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, []byte("digest-sized-input-000000000000"), roundTripped) {
		t.Errorf("round-tripped signature failed to verify")
	}
}

func TestToFixedRejectsMalformedDER(t *testing.T) {
	if _, err := ToFixed([]byte("not der"), 32); err == nil {
		t.Errorf("ToFixed accepted malformed DER")
	}
}

func TestToDERRejectsWrongLength(t *testing.T) {
	if _, err := ToDER(make([]byte, 10), 32); err == nil {
		t.Errorf("ToDER accepted a signature of the wrong length")
	}
}

// A DER signature whose R or S doesn't fit the curve, isn't positive,
// or has bytes after it is an error, never a panic.
func TestToFixedRejectsOutOfRangeValues(t *testing.T) {
	big33 := new(big.Int).Lsh(big.NewInt(1), 8*32) // 2^256: 33 bytes
	one := big.NewInt(1)
	for name, sig := range map[string]signature{
		"R too wide": {R: big33, S: one},
		"S too wide": {R: one, S: big33},
		"R zero":     {R: big.NewInt(0), S: one},
		"S negative": {R: one, S: big.NewInt(-1)},
	} {
		der, err := asn1.Marshal(sig)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ToFixed(der, 32); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	der, _ := asn1.Marshal(signature{R: one, S: one})
	if _, err := ToFixed(append(der, 0), 32); err == nil {
		t.Error("accepted trailing bytes")
	}
}
