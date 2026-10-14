package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// A key for another algorithm than ECDH-ES isn't encrypted to, even
// listed first (OpenID4VP §8.3); one without alg still is.
func TestSelectResponseEncryptionKey_Alg(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(kid, alg string) json.RawMessage {
		var m map[string]any
		raw, _ := json.Marshal(pub)
		_ = json.Unmarshal(raw, &m)
		m["kid"], m["use"] = kid, "enc"
		if alg != "" {
			m["alg"] = alg
		}
		out, _ := json.Marshal(m)
		return out
	}
	if _, kid, err := selectResponseEncryptionKey([]json.RawMessage{entry("kw", "ECDH-ES+A128KW"), entry("es", "ECDH-ES")}); err != nil || kid != "es" {
		t.Errorf("chose %q, %v; want the ECDH-ES key", kid, err)
	}
	if _, kid, err := selectResponseEncryptionKey([]json.RawMessage{entry("no-alg", "")}); err != nil || kid != "no-alg" {
		t.Errorf("a key without alg: %q, %v; want it used", kid, err)
	}
	if _, _, err := selectResponseEncryptionKey([]json.RawMessage{entry("kw", "ECDH-ES+A256KW")}); err == nil {
		t.Error("encrypted to a key-wrap key")
	}
}

// The strongest content encryption both sides support (HAIP 1.0 §5),
// A128GCM when the Verifier lists none, and none it can't do.
func TestResponseEnc(t *testing.T) {
	for offered, want := range map[string]string{
		`["A128GCM","A256GCM"]`:       "A256GCM",
		`["A128GCM"]`:                 "A128GCM",
		`["A128CBC-HS256","A192GCM"]`: "A192GCM",
		`[]`:                          "A128GCM",
	} {
		var list []string
		_ = json.Unmarshal([]byte(offered), &list)
		if got, err := responseEnc(list); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %s", offered, got, err, want)
		}
	}
	if _, err := responseEnc([]string{"A128CBC-HS256"}); err == nil {
		t.Error("chose an enc this wallet can't do")
	}
}
