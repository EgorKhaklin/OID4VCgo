package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func prefixed(prefix, b []byte) []byte { return append(append([]byte{}, prefix...), b...) }

// A COSE_Sign1 is accepted untagged or with its own tag (18), and
// refused behind any other tag: COSE_Mac0's (17), the CWT tag (61), an
// unassigned one, or its own tag twice. Skipping them would verify
// bytes labelled as something else.
func TestSign1RefusesForeignTags(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	untagged, err := Sign(ES256, key, Headers{}, Headers{}, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	tagged := prefixed([]byte{0xd2}, untagged)

	verify := func(b []byte) error { _, _, _, err := Verify(ES256, &key.PublicKey, b, nil); return err }
	decode := func(b []byte) error { _, _, _, err := DecodeUnverified(b); return err }
	for name, b := range map[string][]byte{"untagged": untagged, "tagged 18": tagged} {
		if err := verify(b); err != nil {
			t.Errorf("Verify(%s) = %v, want accepted", name, err)
		}
		if err := decode(b); err != nil {
			t.Errorf("DecodeUnverified(%s) = %v, want accepted", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"tag 17 (COSE_Mac0)": prefixed([]byte{0xd1}, untagged),
		"tag 61 (CWT)":       prefixed([]byte{0xd8, 0x3d}, untagged),
		"tag 61 around 18":   prefixed([]byte{0xd8, 0x3d}, tagged),
		"tag 99":             prefixed([]byte{0xd8, 0x63}, untagged),
		"tag 18 twice":       prefixed([]byte{0xd2}, tagged),
		"tag 18, long form":  prefixed([]byte{0xd8, 0x12}, untagged),
	} {
		if verify(b) == nil {
			t.Errorf("Verify accepted %s", name)
		}
		if decode(b) == nil {
			t.Errorf("DecodeUnverified accepted %s", name)
		}
		// VerifyTagged decodes the tag, so tag 18's long form is still 18.
		if _, _, _, err := VerifyTagged(ES256, &key.PublicKey, b, nil); err == nil && name != "tag 18, long form" {
			t.Errorf("VerifyTagged accepted %s", name)
		}
	}
}

// A COSE_Mac0 is accepted untagged or with its own tag (17), and
// refused behind COSE_Sign1's (18) or any other.
func TestMac0RefusesForeignTags(t *testing.T) {
	key := make([]byte, 32)
	mac0, err := ComputeMAC(key, Headers{}, Headers{}, []byte("hi"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"untagged": mac0, "tagged 17": prefixed([]byte{0xd1}, mac0)} {
		if _, _, err := VerifyMAC(key, b, []byte("hi"), nil); err != nil {
			t.Errorf("VerifyMAC(%s) = %v, want accepted", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"tag 18 (COSE_Sign1)": prefixed([]byte{0xd2}, mac0),
		"tag 61 (CWT)":        prefixed([]byte{0xd8, 0x3d}, mac0),
		"tag 17 twice":        prefixed([]byte{0xd1, 0xd1}, mac0),
	} {
		if _, _, err := VerifyMAC(key, b, []byte("hi"), nil); err == nil {
			t.Errorf("VerifyMAC accepted %s", name)
		}
	}
}
