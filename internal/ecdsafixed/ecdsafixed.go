package ecdsafixed

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// signature is the ASN.1 DER structure Go's crypto.Signer produces for
// an ECDSA key.
type signature struct {
	R, S *big.Int
}

// ToFixed converts a DER-encoded ECDSA signature to size-byte-per-value
// big-endian R||S form.
func ToFixed(der []byte, size int) ([]byte, error) {
	var sig signature
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("ecdsafixed: parse ECDSA signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ecdsafixed: %d bytes after the ECDSA signature", len(rest))
	}
	// FillBytes panics on a value wider than its buffer, and a signer
	// may be the app's (a mobile KeyStore): R and S must each be
	// positive and fit in size bytes (SEC 1 §4.1.3, both in [1, n-1]).
	for _, v := range []*big.Int{sig.R, sig.S} {
		if v.Sign() <= 0 || v.BitLen() > 8*size {
			return nil, fmt.Errorf("ecdsafixed: ECDSA signature value out of range for a %d-byte curve", size)
		}
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// ToDER converts a fixed-width big-endian R||S ECDSA signature (2*size
// bytes) to ASN.1 DER form.
func ToDER(fixed []byte, size int) ([]byte, error) {
	if len(fixed) != 2*size {
		return nil, fmt.Errorf("ecdsafixed: signature has length %d, want %d", len(fixed), 2*size)
	}
	r := new(big.Int).SetBytes(fixed[:size])
	s := new(big.Int).SetBytes(fixed[size:])
	return asn1.Marshal(signature{R: r, S: s})
}
