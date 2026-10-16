package sdjwtvc

import (
	"crypto/ecdsa"
	"encoding/json"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"testing"
)

// mustEncodeJSONArray base64url-encodes arr as sdjwtvc's own Disclosure
// encoding would, for constructing malformed-on-purpose test fixtures
// (e.g. a disclosure array using a reserved claim name) that this
// package's own constructors correctly refuse to build.
func mustEncodeJSONArray(t *testing.T, arr []any) string {
	t.Helper()
	raw, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b64.EncodeToString(raw)
}

// signRawSDJWT signs payload as an Issuer-signed JWT with no
// disclosures, for payloads Issue won't produce.
func signRawSDJWT(t *testing.T, payload map[string]any) (string, *ecdsa.PublicKey) {
	t.Helper()
	key := testKey(t)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := jose.Sign(jose.ES256, key, issuerJWTHeader(IssueOptions{}), raw)
	if err != nil {
		t.Fatal(err)
	}
	return jwt + "~", &key.PublicKey
}
