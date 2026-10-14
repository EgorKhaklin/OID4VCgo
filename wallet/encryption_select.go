package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// encPreference is the order EncryptionFromMetadata picks a content
// encryption algorithm in, strongest first, among those internal/jwe
// supports.
var encPreference = []jwe.Enc{jwe.A256GCM, jwe.A192GCM, jwe.A128GCM}

// EncryptionFromMetadata chooses how RequestCredential and
// RequestDeferredCredential encrypt a Credential Request, and how they
// ask for an encrypted Credential Response, from the Credential
// Issuer's metadata (§10, §12.2.4) — the choice every Wallet otherwise
// makes by hand.
//
// It encrypts whenever the Issuer offers encryption this package can
// use, required or not: a Credential carries personal data. The
// request is encrypted to the first key in the Issuer's
// credential_request_encryption.jwks this package can use: an EC P-256
// key for ECDH-ES (its alg absent or "ECDH-ES", its use absent or
// "enc"). The strongest content encryption both sides support is
// chosen (A256GCM, then A192GCM, then A128GCM), and no compression is
// asked for.
//
// Encryption the Issuer offers but doesn't require (encryption_required
// false, §12.2.4) is optional: when this package can't use it — no
// usable key, no common content encryption, response encryption without
// ECDH-ES — that direction stays plaintext. A response is only
// encrypted when its request is (§8.2: "Credential Request encryption
// MUST be used if the credential_response_encryption parameter is
// included"), so when request encryption can't be used, neither is
// response encryption. It fails only when the Issuer requires
// encryption this package can't provide. Both are nil when the Issuer
// offers neither, or none this package can use.
func EncryptionFromMetadata(meta oid4vci.Metadata) (*RequestEncryption, *ResponseEncryption, error) {
	req, resp := meta.CredentialRequestEncryption, meta.CredentialResponseEncryption
	requestEncryption, err := requestEncryptionFrom(req)
	if err != nil {
		return nil, nil, err
	}
	if resp == nil {
		return requestEncryption, nil, nil
	}
	responseEncryption, err := responseEncryptionFrom(resp)
	switch {
	case requestEncryption == nil && resp.EncryptionRequired:
		return nil, nil, errors.New("wallet: the issuer requires response encryption, which needs request encryption this wallet can't provide")
	case requestEncryption == nil:
		// §8.2: no encrypted response without an encrypted request.
		return nil, nil, nil
	case err != nil && resp.EncryptionRequired:
		return nil, nil, err
	case err != nil:
		return requestEncryption, nil, nil
	}
	return requestEncryption, responseEncryption, nil
}

// requestEncryptionFrom is how to encrypt the request req offers: nil
// when it offers none, or offers optional encryption this package
// can't use; an error when it requires that.
func requestEncryptionFrom(req *oid4vci.RequestEncryptionMetadata) (*RequestEncryption, error) {
	if req == nil {
		return nil, nil
	}
	recipient, err := requestEncryptionKey(req.JWKS)
	if err == nil {
		var enc jwe.Enc
		if enc, err = preferredEnc("credential_request_encryption", req.EncValuesSupported); err == nil {
			return &RequestEncryption{RecipientJWK: recipient, Enc: enc}, nil
		}
	}
	if req.EncryptionRequired {
		return nil, err
	}
	return nil, nil
}

// responseEncryptionFrom is how to ask for the encrypted response resp
// offers, or why this package can't.
func responseEncryptionFrom(resp *oid4vci.ResponseEncryptionMetadata) (*ResponseEncryption, error) {
	if !slices.Contains(resp.AlgValuesSupported, jwe.ECDHES) {
		return nil, fmt.Errorf("wallet: credential_response_encryption.alg_values_supported %v doesn't include %s", resp.AlgValuesSupported, jwe.ECDHES)
	}
	enc, err := preferredEnc("credential_response_encryption", resp.EncValuesSupported)
	if err != nil {
		return nil, err
	}
	return &ResponseEncryption{Enc: enc}, nil
}

// requestEncryptionKey returns the first key in jwks this package can
// encrypt to, as JSON.
func requestEncryptionKey(jwks oid4vci.JWKSet) (json.RawMessage, error) {
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != jwe.ECDHES) || !usableForEncryption(k.Use, k.KeyOps) {
			continue
		}
		if _, err := k.PublicKey(); err != nil {
			continue
		}
		raw, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("wallet: issuer request encryption key: %w", err)
		}
		return raw, nil
	}
	return nil, errors.New("wallet: credential_request_encryption.jwks has no EC P-256 ECDH-ES key")
}

// usableForEncryption reports whether a JWK's "use" and "key_ops"
// (RFC 7517 §4.2, §4.3), when present, allow encrypting to it: use
// "enc", and key_ops naming an operation ECDH-ES encryption performs.
func usableForEncryption(use string, keyOps []string) bool {
	if use != "" && use != "enc" {
		return false
	}
	if len(keyOps) == 0 {
		return true
	}
	for _, op := range keyOps {
		switch op {
		case "encrypt", "wrapKey", "deriveKey", "deriveBits":
			return true
		}
	}
	return false
}

func preferredEnc(field string, offered []jwe.Enc) (jwe.Enc, error) {
	for _, enc := range encPreference {
		if slices.Contains(offered, enc) {
			return enc, nil
		}
	}
	return "", fmt.Errorf("wallet: %s.enc_values_supported %v has none this wallet supports", field, offered)
}
