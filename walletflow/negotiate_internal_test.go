package walletflow

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo"
)

// chooseProof sends a plain jwt proof where the issuer allows one, and
// a key attestation where it requires one or, under ProfileHAIP, offers
// the attestation proof type: in jwt proofs' key_attestation header
// (HAIP 1.0 §4.5.1), whose aud binds it to the issuer, wherever the
// issuer takes jwt proofs, and as the attestation proof type, which
// names no audience, only where it takes nothing else.
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
	haip := &Wallet{cfg: Config{IssuanceProfile: ProfileHAIP}, deps: Dependencies{Provider: noProvider{}}}
	jwtType := oid4vci.ProofTypeJWT
	attestationOnly := map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeAttestation: attestationType}
	for name, tc := range map[string]struct {
		w     *Wallet
		types map[string]oid4vci.ProofTypeConfiguration
		want  proofPlan
		err   bool
	}{
		"a plain jwt proof":                               {withProvider, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: plainJWT}, proofJWT, false},
		"jwt with key_attestation over attestation":       {withProvider, map[string]oid4vci.ProofTypeConfiguration{jwtType: attestedJWT, oid4vci.ProofTypeAttestation: attestationType}, proofJWTKeyAttestation, false},
		"jwt with key_attestation":                        {withProvider, map[string]oid4vci.ProofTypeConfiguration{jwtType: attestedJWT}, proofJWTKeyAttestation, false},
		"only the attestation proof type":                 {withProvider, attestationOnly, proofAttestation, false},
		"key_attestation, no provider":                    {&Wallet{}, map[string]oid4vci.ProofTypeConfiguration{jwtType: attestedJWT}, 0, true},
		"attestation, no provider":                        {&Wallet{}, attestationOnly, 0, true},
		"haip: plain jwt":                                 {haip, map[string]oid4vci.ProofTypeConfiguration{jwtType: plainJWT}, proofJWT, false},
		"haip: jwt with key_attestation over attestation": {haip, map[string]oid4vci.ProofTypeConfiguration{jwtType: plainJWT, oid4vci.ProofTypeAttestation: attestationType}, proofJWTKeyAttestation, false},
		"haip: only the attestation proof type":           {haip, attestationOnly, proofAttestation, false},
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
