package walletflow

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo"
)

// chooseProof sends a plain jwt proof where the issuer allows one, the
// attestation proof type where it requires a key attestation and offers
// that type, and otherwise jwt proofs carrying the key attestation
// (HAIP 1.0 §4.5.1), which need a Wallet Provider.
func TestChooseProof(t *testing.T) {
	conf := func(types map[string]oid4vci.ProofTypeConfiguration) oid4vci.CredentialConfigurationMetadata {
		return oid4vci.CredentialConfigurationMetadata{
			Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: []string{"jwk"}, ProofTypesSupported: types,
		}
	}
	plainJWT := oid4vci.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{attestationAlg}}
	attestedJWT := oid4vci.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{attestationAlg}, KeyAttestationsRequired: &oid4vci.KeyAttestationRequirement{}}
	attestationType := attestedJWT
	withProvider := &Wallet{deps: Dependencies{Provider: noProvider{}}}
	for name, tc := range map[string]struct {
		w     *Wallet
		types map[string]oid4vci.ProofTypeConfiguration
		want  proofPlan
		err   bool
	}{
		"a plain jwt proof":            {withProvider, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: plainJWT}, proofJWT, false},
		"the attestation proof type":   {withProvider, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: attestedJWT, oid4vci.ProofTypeAttestation: attestationType}, proofAttestation, false},
		"jwt with key_attestation":     {withProvider, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: attestedJWT}, proofJWTKeyAttestation, false},
		"key_attestation, no provider": {&Wallet{}, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: attestedJWT}, 0, true},
	} {
		got, err := tc.w.chooseProof(conf(tc.types))
		if tc.err {
			if !errors.Is(err, ErrProofUnsupported) {
				t.Errorf("%s: %v, want ErrProofUnsupported", name, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

// noProvider is a WalletProvider chooseProof only checks is there.
type noProvider struct{ WalletProvider }
