package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// An x5chain longer than certchain.MaxChainLength is refused when its
// headers are decoded.
func TestX5ChainLengthBound(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := make([][]byte, certchain.MaxChainLength)
	for i := range chain {
		chain[i] = []byte("cert")
	}
	atBound, err := Sign(ES256, key, Headers{}, Headers{X5Chain: chain}, []byte("hi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeUnverified(atBound); err != nil {
		t.Errorf("an x5chain at the bound: %v", err)
	}
	overBound, err := Sign(ES256, key, Headers{}, Headers{X5Chain: append(chain, []byte("cert"))}, []byte("hi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeUnverified(overBound); err == nil {
		t.Error("an x5chain over the bound was decoded")
	}
}
