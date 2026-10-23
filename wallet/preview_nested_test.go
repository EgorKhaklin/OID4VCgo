package wallet_test

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// The preview reports what the Verifier actually receives: selecting
// address.street sends the address Disclosure, and with it the
// plaintext members of address. A plaintext claim the query selects
// isn't listed twice.
func TestPreview_PlaintextInsideADisclosedObject(t *testing.T) {
	ca, caKey := testcert.CA(t, "preview test CA")
	leaf, leafKey := testcert.Leaf(t, "preview test issuer", ca, caKey)
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:x", Exp: &exp,
		Additional: map[string]any{
			"nationality": "DE",
			"address":     sdjwtvc.SD(map[string]any{"street": sdjwtvc.SD("Main St 1"), "country": "DE", "postal_code": "10115"}),
		},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	var q dcql.Query
	if err := json.Unmarshal([]byte(`{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"require_cryptographic_holder_binding":false,
		"claims":[{"path":["address","street"]},{"path":["nationality"]}]}]}`), &q); err != nil {
		t.Fatal(err)
	}
	preview, err := wallet.PreviewPresentation(t.Context(), q, []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: credential}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview) != 1 {
		t.Fatalf("preview = %v", preview)
	}
	got := preview[0].AlwaysDisclosed
	for _, want := range []dcql.Path{{dcql.PathKey("address"), dcql.PathKey("country")}, {dcql.PathKey("address"), dcql.PathKey("postal_code")}} {
		if !slices.ContainsFunc(got, func(p dcql.Path) bool { return slices.Equal(p, want) }) {
			t.Errorf("AlwaysDisclosed = %v, missing %v", got, want)
		}
	}
	if slices.ContainsFunc(got, func(p dcql.Path) bool { return slices.Equal(p, dcql.Path{dcql.PathKey("nationality")}) }) {
		t.Errorf("AlwaysDisclosed = %v lists the selected nationality again", got)
	}
}

// The preview walks into arrays: selecting degrees[*].type sends each
// degree's Disclosure, and with it the element's plaintext university
// and student_id; selecting nationalities[0] of an array disclosed as
// one sends nationalities[1] too. Every claim the Verifier receives is
// in Claims or AlwaysDisclosed, and DisclosedAlong leaves out the
// plaintext claim every presentation sends.
func TestPreview_PlaintextInsideArrays(t *testing.T) {
	ca, caKey := testcert.CA(t, "preview test CA")
	leaf, leafKey := testcert.Leaf(t, "preview test issuer", ca, caKey)
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:x", Exp: &exp,
		Additional: map[string]any{
			"given_name":    "Alice",
			"degrees":       []any{sdjwtvc.SDElement(map[string]any{"type": sdjwtvc.SD("BSc"), "university": "Example Uni", "student_id": "S-12345"})},
			"nationalities": sdjwtvc.SD([]any{"DE", "IR"}),
		},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	var q dcql.Query
	if err := json.Unmarshal([]byte(`{"credentials":[{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"require_cryptographic_holder_binding":false,
		"claims":[{"path":["degrees",null,"type"]},{"path":["nationalities",0]}]}]}`), &q); err != nil {
		t.Fatal(err)
	}
	preview, err := wallet.PreviewPresentation(t.Context(), q, []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: credential}}, nil)
	if err != nil || len(preview) != 1 {
		t.Fatalf("preview = %v, %v", preview, err)
	}
	always, _ := json.Marshal(preview[0].AlwaysDisclosed)
	if want := `[["degrees",0,"student_id"],["degrees",0,"university"],["given_name"],["nationalities",1]]`; string(always) != want {
		t.Errorf("AlwaysDisclosed = %s, want %s", always, want)
	}
	along, _ := json.Marshal(preview[0].DisclosedAlong)
	if want := `[["degrees",0,"student_id"],["degrees",0,"university"],["nationalities",1]]`; string(along) != want {
		t.Errorf("DisclosedAlong = %s, want %s", along, want)
	}

	// What a presentation for these paths sends, resolved, has nothing
	// the preview doesn't show.
	pres, err := sdjwtvc.Parse(credential)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	sel, err := sdjwtvc.SelectDisclosuresAt(payload, sdjwtvc.SHA256, pres.Disclosures, [][]any{{"degrees", nil, "type"}, {"nationalities", 0}})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := sdjwtvc.ResolveDisclosures(payload, sdjwtvc.SHA256, sel)
	if err != nil {
		t.Fatal(err)
	}
	shown := append(slices.Clone(preview[0].Claims), preview[0].AlwaysDisclosed...)
	for _, name := range []string{"given_name", "degrees", "nationalities"} {
		for _, leaf := range jsonLeaves(dcql.Path{dcql.PathKey(name)}, sent[name]) {
			if !slices.ContainsFunc(shown, func(p dcql.Path) bool { return p.Covers(leaf) }) {
				t.Errorf("%v is sent but not previewed", leaf)
			}
		}
	}
}

// jsonLeaves are the leaves of a resolved JSON value v, at path.
func jsonLeaves(path dcql.Path, v any) []dcql.Path {
	var out []dcql.Path
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			out = append(out, jsonLeaves(append(slices.Clone(path), dcql.PathKey(k)), child)...)
		}
	case []any:
		for i, child := range t {
			out = append(out, jsonLeaves(append(slices.Clone(path), dcql.PathIndex(i)), child)...)
		}
	default:
		out = append(out, path)
	}
	return out
}
