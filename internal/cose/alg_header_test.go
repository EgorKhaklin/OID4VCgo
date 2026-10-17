package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// alg must be in the protected header, which the signature covers (RFC
// 9052 §3.1; ISO/IEC 18013-5 §12.3.4 for an mdoc's IssuerAuth). A
// COSE_Sign1 signed correctly but with alg only in the unprotected
// header, where anyone can change it, is refused.
func TestVerifyRefusesAlgOnlyUnprotected(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := encMode.Marshal(map[int]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	toSign, err := encMode.Marshal(sigStructure{Context: "Signature1", BodyProtected: protected, ExternalAAD: []byte{}, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signBytes(ES256, key, toSign)
	if err != nil {
		t.Fatal(err)
	}
	sign1, err := encMode.Marshal(rawSign1{Protected: protected, Unprotected: map[int]interface{}{1: int(ES256)}, Payload: payload, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, sign1, nil); err == nil {
		t.Error("Verify accepted a COSE_Sign1 whose alg is only in the unprotected header")
	}
}

// ESP256 (-9) names the same signature as ES256 (-7), and a COSE_Sign1
// marked with it verifies as ES256 (HAIP 1.0 §7: "-7 or -9"). Another
// algorithm in the header still doesn't.
func TestVerifyAcceptsESP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signWith := func(headerAlg int) []byte {
		protected, err := encMode.Marshal(map[int]interface{}{1: headerAlg})
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte("payload")
		toSign, err := encMode.Marshal(sigStructure{Context: "Signature1", BodyProtected: protected, ExternalAAD: []byte{}, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signBytes(ES256, key, toSign)
		if err != nil {
			t.Fatal(err)
		}
		sign1, err := encMode.Marshal(rawSign1{Protected: protected, Unprotected: map[int]interface{}{}, Payload: payload, Signature: sig})
		if err != nil {
			t.Fatal(err)
		}
		return sign1
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, signWith(-9), nil); err != nil {
		t.Errorf("alg -9: %v", err)
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, signWith(int(EdDSA)), nil); err == nil {
		t.Error("an ES256 signature marked EdDSA verified")
	}
}
