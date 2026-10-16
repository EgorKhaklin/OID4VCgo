package issuer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/issuer"
)

const testVCT = "https://credentials.example.com/identity_credential"

// withTypeMetadata publishes m for the SD-JWT VC configuration.
func withTypeMetadata(m sdjwtvc.TypeMetadata) func(*issuer.Config, *issuer.Dependencies) {
	return func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cc := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		cc.TypeMetadata = &m
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = cc
	}
}

// A credential is checked against its configuration's Type Metadata:
// claims that meet it are issued, claims that break it are refused.
func TestRequestCredential_ChecksTypeMetadata(t *testing.T) {
	meta := sdjwtvc.TypeMetadata{VCT: testVCT, Claims: []sdjwtvc.ClaimMetadata{
		{Path: sdjwtvc.ClaimPath("given_name"), Mandatory: true, SD: sdjwtvc.SDAlways},
	}}
	request := func(claims *sdjwtvc.Claims) error {
		f := newCredentialEndpointFixture(t, withTypeMetadata(meta))
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
			SDJWTClaims:               claims,
		})
		return err
	}
	if err := request(&sdjwtvc.Claims{VCT: testVCT, Additional: map[string]any{"given_name": sdjwtvc.SD("Erika")}}); err != nil {
		t.Errorf("claims that meet the type metadata: %v", err)
	}
	for name, claims := range map[string]*sdjwtvc.Claims{
		"plaintext, but sd always": {VCT: testVCT, Additional: map[string]any{"given_name": "Erika"}},
		"missing, but mandatory":   {VCT: testVCT},
	} {
		if err := request(claims); err == nil {
			t.Errorf("%s: issued", name)
		} else {
			assertIssuerError(t, err, issuer.ErrorCredentialRequestDenied)
		}
	}
}

// New refuses Type Metadata that doesn't belong to its configuration.
func TestNew_ValidatesTypeMetadata(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*issuer.Config, *issuer.Dependencies)
		want   string
	}{
		"another vct":         {withTypeMetadata(sdjwtvc.TypeMetadata{VCT: "urn:example:other"}), "type_metadata is for vct"},
		"an invalid document": {withTypeMetadata(sdjwtvc.TypeMetadata{VCT: testVCT, Claims: []sdjwtvc.ClaimMetadata{{Path: nil}}}), "type_metadata"},
		"on an mdoc configuration": {func(cfg *issuer.Config, _ *issuer.Dependencies) {
			cc := cfg.CredentialConfigurationsSupported[testMdocConfigID]
			cc.TypeMetadata = &sdjwtvc.TypeMetadata{VCT: testVCT}
			cfg.CredentialConfigurationsSupported[testMdocConfigID] = cc
		}, "type_metadata is only for format"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := issuerConfigForTypeMetadata(t)
			tc.mutate(&cfg, &deps)
			if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// issuerConfigForTypeMetadata is the credential endpoint fixture's
// Config and Dependencies, before New.
func issuerConfigForTypeMetadata(t *testing.T) (issuer.Config, issuer.Dependencies) {
	t.Helper()
	var cfg issuer.Config
	var deps issuer.Dependencies
	newCredentialEndpointFixture(t, func(c *issuer.Config, d *issuer.Dependencies) {
		cfg, deps = *c, *d
		cfg.CredentialConfigurationsSupported = map[string]issuer.CredentialConfiguration{}
		for k, v := range c.CredentialConfigurationsSupported {
			cfg.CredentialConfigurationsSupported[k] = v
		}
	})
	return cfg, deps
}
