package sdjwtvc

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A registered claim's sub-claims MUST NOT be selectively disclosable
// either (SD-JWT VC draft-19 §2.2.2.3): Verify refuses an Issuer-signed
// status or cnf holding a digest, whether or not the Holder sends its
// Disclosure, and Issue won't make one.
func TestNestedRegisteredClaimsNotDisclosable(t *testing.T) {
	statusList := map[string]any{"idx": 0, "uri": "https://status.example.com/1"}
	for name, claim := range map[string]struct {
		key   string
		value map[string]any
	}{
		"status.status_list":   {"status", map[string]any{"status_list": SD(statusList)}},
		"cnf.jwk":              {"cnf", map[string]any{"jwk": SD(map[string]any{"kty": "EC"})}},
		"deep in status":       {"status", map[string]any{"status_list": map[string]any{"idx": SD(0), "uri": "https://status.example.com/1"}}},
		"array element in cnf": {"cnf", map[string]any{"x": []any{SDElement("a")}}},
	} {
		t.Run(name, func(t *testing.T) {
			sealed, disclosures, err := sealMap(map[string]any{claim.key: claim.value}, DefaultHashAlg)
			if err != nil {
				t.Fatal(err)
			}
			sealed["vct"] = "urn:example:1"
			sealed["_sd_alg"] = string(DefaultHashAlg)
			bare, key := signRawSDJWT(t, sealed)
			withDisclosures := bare
			for _, d := range disclosures {
				enc, err := d.Encode()
				if err != nil {
					t.Fatal(err)
				}
				withDisclosures += enc + "~"
			}
			for form, sdjwt := range map[string]string{"disclosed": withDisclosures, "withheld": bare} {
				_, _, err := Verify(sdjwt, key, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
				if err == nil || !strings.Contains(err.Error(), claim.key) {
					t.Errorf("%s: Verify = %v, want %s refused", form, err, claim.key)
				}
			}

			claims := Claims{VCT: "urn:example:1"}
			if claim.key == "status" {
				claims.Status = claim.value
			} else {
				claims.CNF = claim.value
			}
			if _, _, err := Issue(testKey(t), jose.ES256, claims, IssueOptions{}); err == nil {
				t.Error("Issue accepted a disclosable sub-claim")
			}
		})
	}
}
