package wallet_test

import (
	"encoding/json"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func TestEncryptionFromMetadata(t *testing.T) {
	ecKey, err := jwk.Marshal(&testP256Key(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ec := oid4vci.JWK{JWK: ecKey, Kid: "ec", Alg: jwe.ECDHES}
	rsa := oid4vci.JWK{JWK: jwk.JWK{Kty: "RSA"}, Kid: "rsa"}
	wrongAlg := oid4vci.JWK{JWK: ecKey, Kid: "wrong-alg", Alg: "ECDH-ES+A128KW"}
	signing := oid4vci.JWK{JWK: ecKey, Kid: "signing", Use: "sig"}
	verifyOnly := oid4vci.JWK{JWK: ecKey, Kid: "verify-only", KeyOps: []string{"verify"}}
	req := func(keys ...oid4vci.JWK) *oid4vci.RequestEncryptionMetadata {
		return &oid4vci.RequestEncryptionMetadata{JWKS: oid4vci.JWKSet{Keys: keys}, EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM}}
	}
	resp := &oid4vci.ResponseEncryptionMetadata{AlgValuesSupported: []jwe.Alg{jwe.ECDHES}, EncValuesSupported: []jwe.Enc{jwe.A128GCM}}

	t.Run("none offered", func(t *testing.T) {
		r, s, err := wallet.EncryptionFromMetadata(oid4vci.Metadata{})
		if r != nil || s != nil || err != nil {
			t.Errorf("= %v, %v, %v; want nothing", r, s, err)
		}
	})
	t.Run("both, picking a usable key and the strongest enc", func(t *testing.T) {
		r, s, err := wallet.EncryptionFromMetadata(oid4vci.Metadata{
			CredentialRequestEncryption: req(rsa, wrongAlg, signing, verifyOnly, ec), CredentialResponseEncryption: resp,
		})
		if err != nil {
			t.Fatal(err)
		}
		var chosen oid4vci.JWK
		if err := json.Unmarshal(r.RecipientJWK, &chosen); err != nil || chosen.Kid != "ec" {
			t.Errorf("recipient key = %s, want the EC ECDH-ES one", r.RecipientJWK)
		}
		if r.Enc != jwe.A256GCM || s == nil || s.Enc != jwe.A128GCM {
			t.Errorf("enc = %v / %+v; want A256GCM for the request, A128GCM for the response", r.Enc, s)
		}
	})
	t.Run("request only", func(t *testing.T) {
		r, s, err := wallet.EncryptionFromMetadata(oid4vci.Metadata{CredentialRequestEncryption: req(ec)})
		if err != nil || r == nil || s != nil {
			t.Errorf("= %v, %v, %v; want request encryption only", r, s, err)
		}
	})
	// Offered encryption this wallet can't use: optional, it's skipped
	// (plaintext that way, and no encrypted response without an
	// encrypted request, §8.2); required, it's an error.
	cases := map[string]struct {
		meta         func(reqRequired, respRequired bool) oid4vci.Metadata
		wantRequest  bool // with nothing required, request encryption is still used
		requiredSide string
	}{
		"response without request": {
			meta: func(_, respRequired bool) oid4vci.Metadata {
				r := *resp
				r.EncryptionRequired = respRequired
				return oid4vci.Metadata{CredentialResponseEncryption: &r}
			},
			requiredSide: "response",
		},
		"no usable key": {
			meta: func(reqRequired, _ bool) oid4vci.Metadata {
				m := req(rsa, wrongAlg, verifyOnly)
				m.EncryptionRequired = reqRequired
				return oid4vci.Metadata{CredentialRequestEncryption: m}
			},
			requiredSide: "request",
		},
		"no common request enc": {
			meta: func(reqRequired, _ bool) oid4vci.Metadata {
				return oid4vci.Metadata{CredentialRequestEncryption: &oid4vci.RequestEncryptionMetadata{
					JWKS: oid4vci.JWKSet{Keys: []oid4vci.JWK{ec}}, EncValuesSupported: []jwe.Enc{"A128CBC-HS256"}, EncryptionRequired: reqRequired,
				}}
			},
			requiredSide: "request",
		},
		"response without ECDH-ES": {
			meta: func(_, respRequired bool) oid4vci.Metadata {
				return oid4vci.Metadata{CredentialRequestEncryption: req(ec), CredentialResponseEncryption: &oid4vci.ResponseEncryptionMetadata{
					AlgValuesSupported: []jwe.Alg{"RSA-OAEP"}, EncValuesSupported: []jwe.Enc{jwe.A128GCM}, EncryptionRequired: respRequired,
				}}
			},
			wantRequest: true, requiredSide: "response",
		},
		"no common response enc": {
			meta: func(_, respRequired bool) oid4vci.Metadata {
				return oid4vci.Metadata{CredentialRequestEncryption: req(ec), CredentialResponseEncryption: &oid4vci.ResponseEncryptionMetadata{
					AlgValuesSupported: []jwe.Alg{jwe.ECDHES}, EncValuesSupported: []jwe.Enc{"A128CBC-HS256"}, EncryptionRequired: respRequired,
				}}
			},
			wantRequest: true, requiredSide: "response",
		},
		"unusable request with usable response": {
			meta: func(reqRequired, respRequired bool) oid4vci.Metadata {
				m := req(rsa)
				m.EncryptionRequired = reqRequired
				r := *resp
				r.EncryptionRequired = respRequired
				return oid4vci.Metadata{CredentialRequestEncryption: m, CredentialResponseEncryption: &r}
			},
			requiredSide: "either",
		},
	}
	for name, tc := range cases {
		r, s, err := wallet.EncryptionFromMetadata(tc.meta(false, false))
		if err != nil || (r != nil) != tc.wantRequest || s != nil {
			t.Errorf("%s, optional: = %v, %v, %v; want request encryption %v, no response encryption, no error", name, r, s, err, tc.wantRequest)
		}
		for _, side := range []string{"request", "response"} {
			if tc.requiredSide != side && tc.requiredSide != "either" {
				continue
			}
			if _, _, err := wallet.EncryptionFromMetadata(tc.meta(side == "request", side == "response")); err == nil {
				t.Errorf("%s, %s encryption required: accepted", name, side)
			}
		}
	}
}
