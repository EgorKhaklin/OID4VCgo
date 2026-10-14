package wallet_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A credential without a holder key is presented without a Key Binding
// JWT only when the query sets require_cryptographic_holder_binding to
// false (OID4VP 6.1); otherwise, and for an mdoc, it's an error rather
// than a panic.
func TestPresentCredentials_WithoutHolderKey(t *testing.T) {
	ca, caKey := testcert.CA(t, "binding test CA")
	leaf, leafKey := testcert.Leaf(t, "binding test issuer", ca, caKey)
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", Exp: &exp, Additional: map[string]any{"given_name": sdjwtvc.SD("Alice")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	held := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: credential}
	query := func(binding string) dcql.Query {
		t.Helper()
		var q dcql.Query
		if err := json.Unmarshal([]byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},`+binding+`"claims":[{"path":["given_name"]}]}]}`), &q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	present := func(q dcql.Query, creds ...wallet.HeldCredential) (map[string][]string, error) {
		return wallet.PresentCredentials(t.Context(), wallet.PresentationRequest{
			Query: q, Credentials: creds, Audience: "https://verifier.example", Nonce: "n",
		})
	}

	vp, err := present(query(`"require_cryptographic_holder_binding":false,`), held)
	if err != nil {
		t.Fatalf("binding not required: %v", err)
	}
	if p := vp["pid"][0]; !strings.HasSuffix(p, "~") || !strings.Contains(p, "~") {
		t.Errorf("presentation %q, want an SD-JWT with no Key Binding JWT", p)
	}
	if _, err := present(query(""), held); !errors.Is(err, wallet.ErrNoMatchingCredential) {
		t.Errorf("a credential without cnf under a query requiring holder binding: %v, want ErrNoMatchingCredential", err)
	}

	m := heldMdoc(t, testmdoc.Issue(t))
	m.HolderKey = nil
	if _, err := present(testmdoc.Query(t), m); err == nil {
		t.Error("presented an mdoc without a device key")
	}
}

// The preview reports which presented mdoc elements the Verifier says
// it will keep (intent_to_retain, OID4VP Appendix B.2.4).
func TestPreviewPresentation_Retained(t *testing.T) {
	held := heldMdoc(t, testmdoc.Issue(t))
	q := testmdoc.Query(t)
	keep := true
	q.Credentials[0].Claims[0].IntentToRetain = &keep
	preview, err := wallet.PreviewPresentation(t.Context(), q, []wallet.HeldCredential{held}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview) != 1 || len(preview[0].Retained) != 1 || !slices.Equal(preview[0].Retained[0], q.Credentials[0].Claims[0].Path) {
		t.Errorf("Retained = %v, want only %v", preview[0].Retained, q.Credentials[0].Claims[0].Path)
	}
}
