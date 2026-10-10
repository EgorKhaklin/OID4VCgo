package jwk

import "bytes"

// ed25519SmallOrder are the encodings of Ed25519's eight points of small
// order (dividing the cofactor 8), with the sign bit cleared, and their
// non-canonical encodings (y ≥ p): libsodium's blocklist.
var ed25519SmallOrder = [][]byte{
	make([]byte, 32),                       // 0: order 4
	append([]byte{1}, make([]byte, 31)...), // 1: the identity, order 1
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}, // order 8
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}, // order 8
	ed25519Near(0xec), // p-1: order 2
	ed25519Near(0xed), // p, non-canonical 0
	ed25519Near(0xee), // p+1, non-canonical 1
}

func ed25519Near(low byte) []byte {
	b := bytes.Repeat([]byte{0xff}, 32)
	b[0], b[31] = low, 0x7f
	return b
}

// IsSmallOrderEd25519 reports whether pub encodes a point of small
// order. crypto/ed25519 accepts such a key, and anyone can make a
// signature that verifies under it for any message (the identity key
// takes R = identity, S = 0): bound to a credential, it binds nothing.
func IsSmallOrderEd25519(pub []byte) bool {
	if len(pub) != 32 {
		return false
	}
	masked := append([]byte(nil), pub...)
	masked[31] &= 0x7f
	for _, b := range ed25519SmallOrder {
		if bytes.Equal(masked, b) {
			return true
		}
	}
	return false
}
