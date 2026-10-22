package oid4vci

import (
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func metadataAt(issuer string) []byte {
	return []byte(`{"credential_issuer":"` + issuer + `","credential_endpoint":"` + issuer + `/credential",` +
		`"nonce_endpoint":"` + issuer + `/nonce","authorization_servers":["` + issuer + `"],"credential_configurations_supported":{}}`)
}

func TestDecodeMetadata_LoopbackHTTP(t *testing.T) {
	local := metadataAt("http://127.0.0.1:8080")

	if _, err := DecodeMetadata(local); err == nil {
		t.Error("DecodeMetadata(loopback http) with no options = nil error, want https required")
	}
	var strict Metadata
	if err := json.Unmarshal(local, &strict); err == nil {
		t.Error("UnmarshalJSON(loopback http) = nil error, want it to stay strict")
	}

	m, err := DecodeMetadata(local, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("DecodeMetadata(loopback http, AllowLoopbackHTTP): %v", err)
	}
	if m.CredentialIssuer.String() != "http://127.0.0.1:8080" || m.NonceEndpoint == nil ||
		len(m.AuthorizationServers) != 1 || m.CredentialEndpoint.String() != "http://127.0.0.1:8080/credential" {
		t.Errorf("decoded %+v", m)
	}
}

func TestDecodeMetadata_AllowLoopbackHTTPStillRejectsRemoteHTTP(t *testing.T) {
	if _, err := DecodeMetadata(metadataAt("http://issuer.example.com"), fapi.AllowLoopbackHTTP()); err == nil {
		t.Error("DecodeMetadata(non-loopback http, AllowLoopbackHTTP) = nil error, want error")
	}
}

// Metadata another parser would read differently — a member twice, or
// one named like a known member in another case — is refused: signed
// metadata (§12.2.3) is decoded this way once its signature checks.
func TestDecodeMetadata_RefusesAmbiguousMembers(t *testing.T) {
	valid := metadataAt("https://issuer.example")
	if _, err := DecodeMetadata(valid); err != nil {
		t.Fatal(err)
	}
	for name, prefix := range map[string]string{
		"credential_endpoint twice":        `{"credential_endpoint":"https://attacker.example/credential",`,
		"case-variant credential_endpoint": `{"Credential_Endpoint":"https://attacker.example/credential",`,
	} {
		if _, err := DecodeMetadata(append([]byte(prefix), valid[1:]...)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
