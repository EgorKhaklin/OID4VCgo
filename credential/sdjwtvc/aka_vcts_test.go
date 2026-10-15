package sdjwtvc

import (
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

const (
	akaTestVCT     = "urn:example:eudi:pid:aendgard:1"
	akaTestGeneral = "urn:example:eudi:pid"
)

// An issued aka_vcts is plaintext in the Issuer-signed JWT and comes
// back from Verify (SD-JWT VC draft-19 §2.2.2.2, §2.2.2.3).
func TestAkaVCTs_IssuedAndVerified(t *testing.T) {
	key := testKey(t)
	sdjwt, disclosures, err := Issue(key, jose.ES256, Claims{VCT: akaTestVCT, AkaVCTs: []string{akaTestGeneral}}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(disclosures) != 0 {
		t.Errorf("aka_vcts was made disclosable: %v", disclosures)
	}
	payload, _, err := Verify(sdjwt, &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	aka, _ := payload["aka_vcts"].([]any)
	if len(aka) != 1 || aka[0] != akaTestGeneral {
		t.Errorf("aka_vcts = %v, want [%s]", payload["aka_vcts"], akaTestGeneral)
	}
}

// Issue refuses an aka_vcts draft-19 §2.2.2.2 forbids, and one set
// through Additional.
func TestAkaVCTs_IssueRefusesInvalid(t *testing.T) {
	key := testKey(t)
	for name, claims := range map[string]Claims{
		"empty":         {VCT: akaTestVCT, AkaVCTs: []string{}},
		"an empty type": {VCT: akaTestVCT, AkaVCTs: []string{""}},
		"its own vct":   {VCT: akaTestVCT, AkaVCTs: []string{akaTestGeneral, akaTestVCT}},
		"in Additional": {VCT: akaTestVCT, Additional: map[string]any{"aka_vcts": []string{akaTestGeneral}}},
	} {
		if _, _, err := Issue(key, jose.ES256, claims, IssueOptions{}); err == nil {
			t.Errorf("%s: Issue accepted it", name)
		}
	}
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

// Verify refuses an Issuer-signed aka_vcts draft-19 §2.2.2.2 forbids.
func TestAkaVCTs_VerifyRefusesInvalid(t *testing.T) {
	for name, aka := range map[string]any{
		"not an array":  akaTestGeneral,
		"empty":         []any{},
		"not strings":   []any{1},
		"an empty type": []any{""},
		"its own vct":   []any{akaTestGeneral, akaTestVCT},
	} {
		sdjwt, key := signRawSDJWT(t, map[string]any{"vct": akaTestVCT, "aka_vcts": aka})
		_, _, err := Verify(sdjwt, key, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
		if err == nil || !strings.Contains(err.Error(), "aka_vcts") {
			t.Errorf("%s: Verify = %v, want an aka_vcts refusal", name, err)
		}
	}
}

// aka_vcts is one of the claims an Issuer MUST NOT make selectively
// disclosable (draft-19 §2.2.2.3).
func TestAkaVCTs_NotDisclosable(t *testing.T) {
	if !nonDisclosableClaims["aka_vcts"] || !reservedTopLevelClaims["aka_vcts"] {
		t.Fatal("aka_vcts isn't reserved")
	}
	sealed, disclosures, err := sealMap(map[string]any{"aka_vcts": SD([]any{akaTestGeneral})}, DefaultHashAlg)
	if err != nil {
		t.Fatal(err)
	}
	sealed["vct"] = akaTestVCT
	sealed["_sd_alg"] = string(DefaultHashAlg)
	sdjwt, key := signRawSDJWT(t, sealed)
	for _, d := range disclosures {
		enc, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		sdjwt += enc + "~"
	}
	_, _, err = Verify(sdjwt, key, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err == nil || !strings.Contains(err.Error(), "aka_vcts") {
		t.Errorf("Verify = %v, want aka_vcts refused as disclosable", err)
	}
}
