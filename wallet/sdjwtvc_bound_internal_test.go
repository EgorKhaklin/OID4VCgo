package wallet

import (
	"encoding/base64"
	"testing"
)

// A credential whose cnf can't be read counts as bound: it's never
// presented without a KB-JWT on that account.
func TestSDJWTVCBound_UnreadableCountsAsBound(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	for name, credential := range map[string]string{
		"not an SD-JWT":      "",
		"not a JWS":          "abc~",
		"payload isn't JSON": b64([]byte(`{"alg":"ES256"}`)) + "." + b64([]byte("not json")) + ".c2ln~",
	} {
		if !sdjwtvcBound(credential) {
			t.Errorf("%s: counted as unbound", name)
		}
	}
	unbound := b64([]byte(`{"alg":"ES256"}`)) + "." + b64([]byte(`{"vct":"x"}`)) + ".c2ln~"
	bound := b64([]byte(`{"alg":"ES256"}`)) + "." + b64([]byte(`{"vct":"x","cnf":{}}`)) + ".c2ln~"
	if sdjwtvcBound(unbound) || !sdjwtvcBound(bound) {
		t.Error("cnf misread")
	}
}
