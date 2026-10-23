package sdjwtvc

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// issuedPayload is sdjwt's Issuer-signed JWT payload, as a Verifier
// receives it before resolving any Disclosure.
func issuedPayload(t *testing.T, sdjwt string) map[string]any {
	t.Helper()
	_, raw, err := jose.DecodeUnverified(strings.SplitN(sdjwt, "~", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

// sortedSDDigests is object's _sd array, checked to be sorted strings of a
// SHA-256 digest's base64url length.
func sortedSDDigests(t *testing.T, object any) []string {
	t.Helper()
	m, ok := object.(map[string]any)
	if !ok {
		t.Fatalf("%v isn't an object", object)
	}
	raw, _ := m["_sd"].([]any)
	out := make([]string, len(raw))
	for i, d := range raw {
		s, ok := d.(string)
		if !ok || len(s) != 43 {
			t.Fatalf("_sd[%d] = %v, want a base64url SHA-256 digest", i, d)
		}
		out[i] = s
	}
	if !slices.IsSorted(out) {
		t.Errorf("_sd %v isn't sorted", out)
	}
	return out
}

// disclosureValue is the value of the object Disclosure named name.
func disclosureValue(t *testing.T, disclosures []Disclosure, name string) any {
	t.Helper()
	for _, d := range disclosures {
		if !d.IsArrayElement() && d.Name == name {
			return d.Value
		}
	}
	t.Fatalf("no Disclosure for %q", name)
	return nil
}

// NestedDecoys adds decoys to every _sd array below the top level —
// in a plaintext object and in a disclosed value — and none to the
// top level's or to an object without one; the credential still
// verifies to the same claims.
func TestIssue_NestedDecoys(t *testing.T) {
	issuerKey := testKey(t)
	claims := Claims{VCT: "vc-type", Additional: map[string]any{
		"given_name": SD("Erika"),
		"address":    map[string]any{"street": SD("Heidestraße 17"), "locality": SD("Köln")},
		"plain":      map[string]any{"a": "1"},
		"nationality": SD(map[string]any{
			"country": SD("DE"),
		}),
	}}
	calls := 0
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{NestedDecoys: func() (int, error) {
		calls++
		return 2, nil
	}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if calls != 2 {
		t.Errorf("NestedDecoys called %d times, want once for each nested _sd array (2)", calls)
	}
	payload := issuedPayload(t, sdjwt)
	if got := len(sortedSDDigests(t, payload)); got != 2 {
		t.Errorf("top-level _sd has %d digests, want 2: no nested decoys at the top level", got)
	}
	if got := len(sortedSDDigests(t, payload["address"])); got != 4 {
		t.Errorf("address _sd has %d digests, want 2 claims + 2 decoys", got)
	}
	if _, ok := payload["plain"].(map[string]any)["_sd"]; ok {
		t.Error("an object without selectively disclosable claims got an _sd array")
	}
	if got := len(sortedSDDigests(t, disclosureValue(t, disclosures, "nationality"))); got != 3 {
		t.Errorf("the disclosed nationality's _sd has %d digests, want 1 claim + 2 decoys", got)
	}

	verified, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := map[string]any{"locality": "Köln", "street": "Heidestraße 17"}
	if got := verified["address"]; !reflect.DeepEqual(got, want) {
		t.Errorf("address = %v, want %v", got, want)
	}
	if got := verified["nationality"]; !reflect.DeepEqual(got, map[string]any{"country": "DE"}) {
		t.Errorf("nationality = %v", got)
	}
}

// WithDecoys pads an object's _sd array by exactly n — creating one for
// an object with no selectively disclosable claim, typed maps included
// — and the credential verifies to the claims without them.
func TestIssue_WithDecoys(t *testing.T) {
	issuerKey := testKey(t)
	claims := Claims{VCT: "vc-type", Additional: map[string]any{
		"age_equal_or_over": WithDecoys(map[string]any{"18": SD(true), "21": SD(false)}, 3),
		"padded":            WithDecoys(map[string]string{"a": "1"}, 2),
		"inside":            SD(WithDecoys(map[string]any{"b": SD("2")}, 1)),
	}}
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	payload := issuedPayload(t, sdjwt)
	if got := len(sortedSDDigests(t, payload["age_equal_or_over"])); got != 5 {
		t.Errorf("age_equal_or_over _sd has %d digests, want 2 claims + 3 decoys", got)
	}
	if got := len(sortedSDDigests(t, payload["padded"])); got != 2 {
		t.Errorf("padded _sd has %d digests, want 2 decoys", got)
	}
	if got := len(sortedSDDigests(t, disclosureValue(t, disclosures, "inside"))); got != 2 {
		t.Errorf("the disclosed object's _sd has %d digests, want 1 claim + 1 decoy", got)
	}

	verified, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for name, want := range map[string]any{
		"age_equal_or_over": map[string]any{"18": true, "21": false},
		"padded":            map[string]any{"a": "1"},
		"inside":            map[string]any{"b": "2"},
	} {
		if got := verified[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
}

// A credential whose only digests are a WithDecoys object's decoys
// still names their algorithm in _sd_alg.
func TestIssue_WithDecoysAloneSetsSDAlg(t *testing.T) {
	issuerKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type", Additional: map[string]any{
		"o": WithDecoys(map[string]any{"a": "1"}, 2),
	}}, IssueOptions{HashAlg: SHA384, Decoys: 3})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	payload := issuedPayload(t, sdjwt)
	if payload["_sd_alg"] != string(SHA384) {
		t.Errorf("_sd_alg = %v, want %s", payload["_sd_alg"], SHA384)
	}
	if _, ok := payload["_sd"]; ok {
		t.Error("top-level _sd present without a selectively disclosable claim")
	}
	if _, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Every decoy is a distinct digest.
func TestIssue_DecoysAreDistinct(t *testing.T) {
	issuerKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type", Additional: map[string]any{
		"o": WithDecoys(map[string]any{"a": SD("1")}, 50),
	}}, IssueOptions{NestedDecoys: func() (int, error) { return 50, nil }})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	digests := sortedSDDigests(t, issuedPayload(t, sdjwt)["o"])
	if len(digests) != 101 || len(slices.Compact(digests)) != 101 {
		t.Errorf("%d digests, %d distinct; want 101 distinct", len(digests), len(slices.Compact(digests)))
	}
}

// Issue refuses decoy counts it can't honor, a WithDecoys around
// anything but an object, a WithDecoys in a registered claim, and a
// NestedDecoys failure.
func TestIssue_RejectsInvalidNestedDecoys(t *testing.T) {
	issuerKey := testKey(t)
	sdClaims := func(v any) Claims {
		return Claims{VCT: "vc-type", Additional: map[string]any{"o": v}}
	}
	nested := map[string]any{"a": SD("1")}
	failing := errors.New("no randomness")
	for name, tc := range map[string]struct {
		claims Claims
		opts   IssueOptions
	}{
		"negative WithDecoys":  {sdClaims(WithDecoys(nested, -1)), IssueOptions{}},
		"WithDecoys too many":  {sdClaims(WithDecoys(nested, MaxDecoys+1)), IssueOptions{}},
		"WithDecoys on string": {sdClaims(WithDecoys("x", 1)), IssueOptions{}},
		"WithDecoys on array":  {sdClaims(WithDecoys([]any{"x"}, 1)), IssueOptions{}},
		"WithDecoys in status": {Claims{VCT: "vc-type", Status: map[string]any{"status_list": WithDecoys(map[string]any{}, 1)}}, IssueOptions{}},
		"negative nested":      {sdClaims(nested), IssueOptions{NestedDecoys: func() (int, error) { return -1, nil }}},
		"nested too many":      {sdClaims(nested), IssueOptions{NestedDecoys: func() (int, error) { return MaxDecoys + 1, nil }}},
		"nested fails":         {sdClaims(nested), IssueOptions{NestedDecoys: func() (int, error) { return 0, failing }}},
	} {
		if _, _, err := Issue(issuerKey, jose.ES256, tc.claims, tc.opts); err == nil {
			t.Errorf("%s: Issue succeeded, want an error", name)
		}
	}
}

// Type metadata sees through WithDecoys: a claim inside the padded
// object is found, and still selectively disclosable.
func TestCheckTypeMetadata_SeesThroughWithDecoys(t *testing.T) {
	claims := Claims{VCT: "vc-type", Additional: map[string]any{
		"age_equal_or_over": WithDecoys(map[string]any{"18": SD(true)}, 4),
	}}
	m := TypeMetadata{Claims: []ClaimMetadata{{Path: ClaimPath("age_equal_or_over", "18"), Mandatory: true, SD: SDAlways}}}
	if err := CheckTypeMetadata(claims, m); err != nil {
		t.Errorf("CheckTypeMetadata: %v", err)
	}
}
