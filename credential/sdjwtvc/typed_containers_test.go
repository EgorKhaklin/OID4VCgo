package sdjwtvc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A marker inside a typed container ([]map[string]any, map[string][]any)
// is sealed as one in map[string]any or []any is, so the claim is
// selectively disclosable, not encoded as {}. The metadata check, which
// walks the same containers, agrees with what's issued.
func TestIssue_SealsMarkersInTypedContainers(t *testing.T) {
	key := testKey(t)
	meta := TypeMetadata{VCT: "urn:x", Claims: []ClaimMetadata{{Path: []any{"items", nil, "n"}, SD: SDAlways}}}
	claims := Claims{VCT: "urn:x", Additional: map[string]any{
		"items": []map[string]any{{"n": SD("secret")}},
		"tags":  map[string][]any{"t": {SDElement("a"), "b"}},
	}}
	sdjwt, disclosures, err := Issue(key, jose.ES256, claims, IssueOptions{TypeMetadata: &meta})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(disclosures) != 2 {
		t.Fatalf("%d disclosures, want 2", len(disclosures))
	}
	payload, _, err := Verify(sdjwt, &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	items, _ := payload["items"].([]any)
	first, _ := items[0].(map[string]any)
	tags, _ := payload["tags"].(map[string]any)
	if len(items) != 1 || first["n"] != "secret" {
		t.Errorf("items = %v, want [{n: secret}]", payload["items"])
	}
	if got, _ := json.Marshal(tags["t"]); string(got) != `["a","b"]` {
		t.Errorf("tags.t = %s, want [\"a\",\"b\"]", got)
	}
}

// Typed values with nothing to seal encode exactly as before: a typed
// map or slice the same JSON as map[string]any or []any, []byte as
// base64, and a json.Marshaler as itself.
func TestIssue_TypedValuesEncodeAsBefore(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	claims := Claims{VCT: "urn:x", Additional: map[string]any{
		"list": []string{"x", "y"}, "map": map[string]int{"k": 1}, "bytes": []byte{1, 2, 3},
		"when": when, "nil_list": []string(nil), "nested": []map[string]string{{"a": "b"}},
	}}
	sdjwt, _, err := Issue(testKey(t), jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := jose.DecodeUnverified(strings.TrimSuffix(sdjwt, "~"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for claim, want := range map[string]string{
		"list": `["x","y"]`, "map": `{"k":1}`, "bytes": `"AQID"`, "when": `"2026-01-02T03:04:05Z"`, "nil_list": `null`, "nested": `[{"a":"b"}]`,
	} {
		if string(got[claim]) != want {
			t.Errorf("%s = %s, want %s", claim, got[claim], want)
		}
	}
}

// A marker Issue can't seal (inside a struct, an array or a
// json.Marshaler) is refused, not encoded as {}; a pointer cycle
// doesn't hang the check.
func TestIssue_RefusesMarkersItCantSeal(t *testing.T) {
	type wrapper struct{ V any }
	type node struct{ Next *node }
	cycle := &node{}
	cycle.Next = cycle
	for name, value := range map[string]any{
		"in a struct":            wrapper{V: SD("x")},
		"in a struct in a slice": []any{wrapper{V: SD("x")}},
		"in an array":            [1]any{SD("x")},
	} {
		if _, _, err := Issue(testKey(t), jose.ES256, Claims{VCT: "urn:x", Additional: map[string]any{"c": value}}, IssueOptions{}); err == nil || !strings.Contains(err.Error(), "can't seal") {
			t.Errorf("%s: Issue = %v, want it refused", name, err)
		}
	}
	if _, _, err := Issue(testKey(t), jose.ES256, Claims{VCT: "urn:x", Additional: map[string]any{"c": wrapper{V: cycle}}}, IssueOptions{}); err == nil {
		t.Log("a pointer cycle without markers is left to json.Marshal")
	}
}
