package sdjwtvc

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

func metaFor(claims ...ClaimMetadata) TypeMetadata {
	return TypeMetadata{VCT: "urn:example:pid", Claims: claims}
}

// CheckTypeMetadata holds claims to their metadata's mandatory and sd
// (draft-13 §9; draft-19 §5.6): object properties, array elements by
// index and by null, nested paths, and the registered claims Claims
// sets in plaintext.
func TestCheckTypeMetadata(t *testing.T) {
	claims := Claims{VCT: "urn:example:pid", Iss: "https://issuer.example", Additional: map[string]any{
		"given_name":    SD("Erika"),
		"family_name":   "Mustermann",
		"address":       map[string]any{"street_address": SD("Heidestraße 17"), "country": "DE"},
		"nationalities": []any{SDElement("DE"), "FR"},
		"degrees":       []any{SDElement("BSc"), SDElement("MSc")},
	}}
	for name, tc := range map[string]struct {
		meta TypeMetadata
		want string // "" accepted
	}{
		"no claim metadata":                {metaFor(), ""},
		"mandatory and present":            {metaFor(ClaimMetadata{Path: ClaimPath("family_name"), Mandatory: true}), ""},
		"mandatory and missing":            {metaFor(ClaimMetadata{Path: ClaimPath("birthdate"), Mandatory: true}), "is mandatory"},
		"mandatory nested and missing":     {metaFor(ClaimMetadata{Path: ClaimPath("address", "locality"), Mandatory: true}), "is mandatory"},
		"optional and missing":             {metaFor(ClaimMetadata{Path: ClaimPath("birthdate"), SD: SDAlways}), ""},
		"always, and disclosable":          {metaFor(ClaimMetadata{Path: ClaimPath("given_name"), SD: SDAlways}), ""},
		"always, but plaintext":            {metaFor(ClaimMetadata{Path: ClaimPath("family_name"), SD: SDAlways}), "must be selectively disclosable"},
		"never, and plaintext":             {metaFor(ClaimMetadata{Path: ClaimPath("family_name"), SD: SDNever}), ""},
		"never, but disclosable":           {metaFor(ClaimMetadata{Path: ClaimPath("given_name"), SD: SDNever}), "must not be selectively disclosable"},
		"allowed, either way":              {metaFor(ClaimMetadata{Path: ClaimPath("given_name"), SD: SDAllowed}, ClaimMetadata{Path: ClaimPath("family_name")}), ""},
		"nested always, disclosable":       {metaFor(ClaimMetadata{Path: ClaimPath("address", "street_address"), SD: SDAlways}), ""},
		"nested never, but disclosable":    {metaFor(ClaimMetadata{Path: ClaimPath("address", "street_address"), SD: SDNever}), "must not"},
		"every element always, all are":    {metaFor(ClaimMetadata{Path: []any{"degrees", nil}, SD: SDAlways}), ""},
		"every element always, one isn't":  {metaFor(ClaimMetadata{Path: []any{"nationalities", nil}, SD: SDAlways}), "must be selectively disclosable"},
		"element by index, disclosable":    {metaFor(ClaimMetadata{Path: []any{"nationalities", 0}, SD: SDAlways}), ""},
		"element by JSON index, plaintext": {metaFor(ClaimMetadata{Path: []any{"nationalities", float64(1)}, SD: SDAlways}), "must be selectively disclosable"},
		"the array itself, plaintext":      {metaFor(ClaimMetadata{Path: ClaimPath("nationalities"), SD: SDNever}), ""},
		"iss always, but it's plaintext":   {metaFor(ClaimMetadata{Path: ClaimPath("iss"), SD: SDAlways}), "must be selectively disclosable"},
		"iss mandatory and set":            {metaFor(ClaimMetadata{Path: ClaimPath("iss"), Mandatory: true}), ""},
		"exp mandatory but unset":          {metaFor(ClaimMetadata{Path: ClaimPath("exp"), Mandatory: true}), "is mandatory"},
		"another vct":                      {TypeMetadata{VCT: "urn:example:other"}, "type metadata is for vct"},
		"a path element of a bool":         {metaFor(ClaimMetadata{Path: []any{"nationalities", true}}), "path element"},
	} {
		err := CheckTypeMetadata(claims, tc.meta)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v, want accepted", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// Issue with IssueOptions.TypeMetadata refuses claims that break it,
// and issues claims that meet it.
func TestIssue_ChecksTypeMetadata(t *testing.T) {
	meta := metaFor(ClaimMetadata{Path: ClaimPath("given_name"), Mandatory: true, SD: SDAlways})
	key := testKey(t)
	if _, _, err := Issue(key, jose.ES256, Claims{VCT: "urn:example:pid", Additional: map[string]any{"given_name": SD("Erika")}}, IssueOptions{TypeMetadata: &meta}); err != nil {
		t.Errorf("claims that meet the metadata: %v", err)
	}
	if _, _, err := Issue(key, jose.ES256, Claims{VCT: "urn:example:pid", Additional: map[string]any{"given_name": "Erika"}}, IssueOptions{TypeMetadata: &meta}); err == nil {
		t.Error("issued a plaintext given_name the metadata says is always selectively disclosable")
	}
	if _, _, err := Issue(key, jose.ES256, Claims{VCT: "urn:example:pid"}, IssueOptions{TypeMetadata: &meta}); err == nil {
		t.Error("issued without the mandatory given_name")
	}
}
