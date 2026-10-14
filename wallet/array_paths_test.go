package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A claims path into an array (["nationalities", null], or an index)
// presents exactly those elements, where it used to be refused.
func TestPresentSDJWTVCSelective_ArrayPaths(t *testing.T) {
	ca, caKey := testcert.CA(t, "array test CA")
	leaf, leafKey := testcert.Leaf(t, "array test issuer", ca, caKey)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"nationalities": []any{sdjwtvc.SDElement("DE"), sdjwtvc.SDElement("FR")},
			"given_name":    sdjwtvc.SD("Alice"),
		},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	held := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: credential, HolderKey: holder, HolderKeyAlg: jose.ES256}
	disclosed := func(path dcql.Path) map[string]any {
		t.Helper()
		presentation, err := wallet.PresentSDJWTVCSelective(held, "https://verifier.example", "nonce", []dcql.Path{path})
		if err != nil {
			t.Fatalf("PresentSDJWTVCSelective(%v): %v", path, err)
		}
		pres, err := sdjwtvc.Parse(presentation)
		if err != nil {
			t.Fatal(err)
		}
		_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
		if err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		resolved, err := sdjwtvc.ResolveDisclosures(payload, sdjwtvc.SHA256, pres.Disclosures)
		if err != nil {
			t.Fatal(err)
		}
		return resolved
	}
	all := disclosed(dcql.Path{dcql.PathKey("nationalities"), dcql.Wildcard})
	if fmt.Sprint(all["nationalities"]) != "[DE FR]" {
		t.Errorf("wildcard: nationalities = %v", all["nationalities"])
	}
	if _, leaked := all["given_name"]; leaked {
		t.Error("given_name disclosed, unasked")
	}
	if second := disclosed(dcql.Path{dcql.PathKey("nationalities"), dcql.PathIndex(1)}); fmt.Sprint(second["nationalities"]) != "[FR]" {
		t.Errorf("index 1: nationalities = %v", second["nationalities"])
	}
}
