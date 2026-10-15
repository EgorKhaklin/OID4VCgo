package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A received credential whose x5c includes the trust anchor is refused
// (HAIP 1.0: the sender leaves it out). sdjwtvc.Issue won't send one, so
// it's signed here directly.
func TestVerifyIssuedCredential_RefusesAnchorInChain(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	leaf, leafKey := testcert.Leaf(t, "issuer", root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"vct": issuedVCT, "exp": time.Now().Add(time.Hour).Unix(), "cnf": map[string]any{"jwk": holderJWK}, "_sd_alg": "sha-256",
	})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(chain ...*x509.Certificate) string {
		x5c := make([]string, len(chain))
		for i, c := range chain {
			x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
		}
		jwt, err := jose.Sign(jose.ES256, leafKey, map[string]any{"typ": "dc+sd-jwt", "x5c": x5c}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return jwt + "~"
	}
	verify := func(credential string) error {
		_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: oid4vci.CredentialConfigurationMetadata{Format: sdjwtvc.CredentialFormat, VCT: issuedVCT, CryptographicBindingMethodsSupported: []string{"jwk"}},
			Credential:    credential, HolderKey: &holder.PublicKey, IssuerRoots: roots,
		})
		return err
	}
	if err := verify(sign(leaf)); err != nil {
		t.Errorf("the leaf alone: %v", err)
	}
	if err := verify(sign(leaf, root)); err == nil {
		t.Error("accepted an x5c that includes the trust anchor")
	}
}
