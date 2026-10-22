package walletflow

import (
	"context"
	"errors"
	"fmt"
	"github.com/idfoundry/oid4vcgo"
	"reflect"
	"slices"
	"testing"
)

// A Token Response's credential_identifiers are kept per configuration,
// from openid_credential details only.
func TestCredentialIdentifiers(t *testing.T) {
	got, err := credentialIdentifiers([]byte(`[
		{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["pid-1","pid-2"],"extra":true},
		{"type":"openid_credential","credential_configuration_id":"mdl"},
		{"type":"payment_initiation","credential_configuration_id":"pid","credential_identifiers":["other"]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"pid": {"pid-1", "pid-2"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("credentialIdentifiers = %v, want %v", got, want)
	}

	if got, err := credentialIdentifiers(nil); got != nil || err != nil {
		t.Errorf("without authorization_details: %v, %v; want none", got, err)
	}
	if _, err := credentialIdentifiers([]byte(`{"type":"openid_credential"}`)); err == nil {
		t.Error("authorization_details that isn't an array accepted")
	}
	if _, err := credentialIdentifiers([]byte(`[{"type":"openid_credential","credential_configuration_id":"pid","Credential_Identifiers":["pid-1"]}]`)); err == nil {
		t.Error("a case-variant credential_identifiers accepted")
	}
}

// Each credential_identifier granted for a configuration is its own
// Credential Request, one Credential Dataset apiece (OpenID4VCI 1.0
// §3.3, §6.2); a configuration granted none is requested by its ID.
func TestRequestUnits(t *testing.T) {
	s := &Issuance{
		offer:       oid4vci.CredentialOffer{CredentialConfigurationIDs: []string{"pid", "mdl"}},
		identifiers: map[string][]string{"pid": {"pid-alice", "pid-bob"}},
	}
	want := []requestUnit{{"pid", "pid-alice"}, {"pid", "pid-bob"}, {"mdl", ""}}
	if got := s.requestUnits(); !slices.Equal(got, want) {
		t.Errorf("requestUnits = %v, want %v", got, want)
	}
	if want[0].key() == want[1].key() {
		t.Error("two units share a key")
	}
}

// A refresh asks for the credential_identifier the credential was
// requested by. Where the wallet can't tell which of several datasets
// its grant issued the credential holds, it refuses rather than guess:
// asking for another would replace the credential with that one.
func TestRefreshIdentifier(t *testing.T) {
	ctx := context.Background()
	alice := StoredCredential{ID: "alice", ConfigurationID: "pid", CredentialIdentifier: "pid-alice", GrantID: "g"}
	bob := StoredCredential{ID: "bob", ConfigurationID: "pid", CredentialIdentifier: "pid-bob", GrantID: "g"}
	legacy := StoredCredential{ID: "legacy", ConfigurationID: "pid", GrantID: "h"}
	legacySibling := StoredCredential{ID: "legacy-2", ConfigurationID: "pid", GrantID: "h"}
	alone := StoredCredential{ID: "alone", ConfigurationID: "pid", GrantID: "i"}
	otherConfig := StoredCredential{ID: "mdl", ConfigurationID: "mdl", GrantID: "i"}
	store := NewMemoryCredentialStore()
	for _, c := range []StoredCredential{alice, bob, legacy, legacySibling, alone, otherConfig} {
		if err := store.Put(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	w := &Wallet{deps: Dependencies{Credentials: store}}
	both := []string{"pid-alice", "pid-bob"}
	for name, tc := range map[string]struct {
		old     StoredCredential
		granted []string
		want    string
		refused bool
	}{
		"its own dataset":                         {bob, both, "pid-bob", false},
		"its dataset no longer granted":           {bob, []string{"pid-alice"}, "", true},
		"no identifiers granted, siblings":        {bob, nil, "", true},
		"not kept, several granted":               {alone, both, "", true},
		"not kept, one granted, siblings":         {legacy, []string{"pid-1"}, "", true},
		"not kept, none granted, siblings":        {legacy, nil, "", true},
		"not kept, one granted, alone":            {alone, []string{"pid-1"}, "pid-1", false},
		"not kept, none granted, alone":           {alone, nil, "", false},
		"by configuration, another configuration": {otherConfig, nil, "", false},
	} {
		got, err := w.refreshIdentifier(ctx, tc.old, tc.granted)
		if tc.refused {
			if !errors.Is(err, ErrReissueRequired) {
				t.Errorf("%s: %q, %v; want ErrReissueRequired", name, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", name, got, err, tc.want)
		}
	}
}

// The credential_identifiers a token grants are requested once each,
// and only up to a bound, per configuration and in all: each is a
// request with its own holder keys and key attestation.
func TestIdentifiersByConfiguration_Bounded(t *testing.T) {
	many := func(prefix string, n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("%s-%d", prefix, i))
		}
		return out
	}
	detail := func(config string, ids ...string) oid4vci.AuthorizationDetail {
		return oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: config, CredentialIdentifiers: ids}
	}
	ids := identifiersByConfiguration([]oid4vci.AuthorizationDetail{detail("pid", "a", "a", "b", "")})
	if !slices.Equal(ids["pid"], []string{"a", "b"}) {
		t.Errorf("duplicates and empties: %v", ids["pid"])
	}
	ids = identifiersByConfiguration([]oid4vci.AuthorizationDetail{detail("pid", many("p", 1000)...), detail("mdl", many("m", 1000)...), detail("x", many("x", 10)...)})
	if len(ids["pid"]) != maxIdentifiersPerConfiguration || len(ids["mdl"]) != maxIdentifiersPerConfiguration || len(ids["x"]) != 0 {
		t.Errorf("per configuration %d, %d, then %d; want %d, %d and none past %d in all", len(ids["pid"]), len(ids["mdl"]), len(ids["x"]), maxIdentifiersPerConfiguration, maxIdentifiersPerConfiguration, maxIdentifiers)
	}
}
