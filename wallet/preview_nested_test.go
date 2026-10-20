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
