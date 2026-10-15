package verifier_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A credential of a derived type whose aka_vcts lists the requested
// type answers the request, through the wallet's matching and the
// verifier's (SD-JWT VC draft-19 §2.2.2.2; OpenID4VP 1.0 §B.3.5); one
// listing neither isn't offered.
func TestAkaVCTs_DerivedTypeAnswersTheRequest(t *testing.T) {
	ca, caKey := testcert.CA(t, "aka issuer CA")
	issuerCert, issuerKey := testcert.Leaf(t, "aka issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(aka []string) wallet.HeldCredential {
		holderKey := testP256Key(t)
		holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
			VCT: "urn:tx:1:derived", AkaVCTs: aka, CNF: map[string]any{"jwk": holderJWK},
			Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
		}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
		if err != nil {
			t.Fatal(err)
		}
		return wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}
	}
	useRoots := func(c *verifier.TransactionsConfig) {
		c.Verify.IssuerKeys = verifier.X5CIssuerKeyResolver{Roots: roots}
	}

	f := newTxFixture(t, useRoots)
	f.held = issue([]string{"urn:tx:1"})
	begun := f.begin("browser-binding-A", false)
	if _, err := f.txs.HandleResponse(context.Background(), f.answer(begun, nil)); err != nil {
		t.Fatalf("HandleResponse: %v", err)
	}
	view, err := f.txs.Lookup(context.Background(), begun.ID, "browser-binding-A")
	if err != nil || view.Status != verifier.TransactionDone || view.Result == nil || view.Result.Credentials[0].Claims["vct"] != "urn:tx:1:derived" {
		t.Fatalf("Lookup = %+v, %v; want the derived credential verified", view, err)
	}

	f = newTxFixture(t, useRoots)
	f.held = issue([]string{"urn:tx:other"})
	if _, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: f.query, Credentials: []wallet.HeldCredential{f.held}, Audience: "x509_hash:v", Nonce: "n",
	}); err == nil {
		t.Error("PresentCredentials offered a credential of neither the requested type nor one it lists")
	}
}
