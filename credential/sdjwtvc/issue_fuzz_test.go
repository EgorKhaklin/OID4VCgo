package sdjwtvc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzIssueReservedNames issues SD-JWT VCs from fuzzed JSON for
// Claims.Additional, Status and CNF, each top-level Additional claim
// made selectively disclosable when sd is set. Whatever Issue accepts
// must sign no name RFC 9901 reserves (_sd, ..., _sd_alg) other than
// where its own sealing puts them — the top level's _sd and _sd_alg,
// with sd — neither in the payload nor in a Disclosure's value, and
// must resolve back to exactly the claims it was given.
func FuzzIssueReservedNames(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"given_name":"Alice","n":12345678901234567890}`), []byte(`{"status_list":{"idx":1,"uri":"https://example.com/sl"}}`), []byte(`{"jwk":{"kty":"EC"}}`), false)
	f.Add([]byte(`{"address":{"street":"Main","list":[1,{"a":null}]}}`), []byte(`null`), []byte(`{}`), true)
	f.Add([]byte(`{"c":{"_sd":["x"]}}`), []byte(`{}`), []byte(`{}`), false)
	f.Add([]byte(`{"c":[{"...":"x"}]}`), []byte(`{"l":[{"_sd_alg":"sha-256"}]}`), []byte(`{"k":[[{"...":"x"}]]}`), true)
	f.Add([]byte(`{"vct":"urn:other"}`), []byte(`{}`), []byte(`{}`), false)

	f.Fuzz(func(t *testing.T, additionalJSON, statusJSON, cnfJSON []byte, sd bool) {
		additional, status, cnf := fuzzObject(additionalJSON), fuzzObject(statusJSON), fuzzObject(cnfJSON)
		claims := Claims{VCT: "urn:x", Status: status, CNF: cnf, Additional: map[string]any{}}
		for k, v := range additional {
			if sd {
				v = SD(v)
			}
			claims.Additional[k] = v
		}
		sdjwt, disclosures, err := Issue(key, jose.ES256, claims, IssueOptions{})
		if err != nil {
			return
		}

		payload := signedPayload(t, sdjwt)
		structural := map[string]any{}
		for k, v := range payload {
			if k != "_sd" && k != "_sd_alg" {
				structural[k] = v
			}
		}
		if name, ok := reservedNameIn(structural); ok {
			t.Fatalf("Issue signed the reserved name %q into the payload", name)
		}
		if _, ok := payload["_sd"]; ok != (sd && len(additional) > 0) {
			t.Fatalf("payload _sd present = %v, with %d claims made selectively disclosable", ok, len(additional))
		}
		for _, d := range disclosures {
			generic, err := toGenericJSON(d.Value)
			if err != nil {
				t.Fatal(err)
			}
			if isReservedName(d.Name) {
				t.Fatalf("a Disclosure names the reserved claim %q", d.Name)
			}
			if name, ok := reservedNameIn(generic); ok {
				t.Fatalf("a Disclosure's value holds the reserved name %q", name)
			}
		}

		resolved, err := ResolveDisclosures(payload, DefaultHashAlg, disclosures)
		if err != nil {
			t.Fatalf("ResolveDisclosures: %v", err)
		}
		delete(resolved, "_sd_alg")
		want := map[string]any{"vct": "urn:x"}
		for k, v := range additional {
			want[k] = v
		}
		if status != nil {
			want["status"] = status
		}
		if cnf != nil {
			want["cnf"] = cnf
		}
		got, err1 := json.Marshal(resolved)
		expected, err2 := json.Marshal(want)
		if err1 != nil || err2 != nil || !bytes.Equal(got, expected) {
			t.Fatalf("resolved claims %s, want %s (%v, %v)", got, expected, err1, err2)
		}
	})
}

// fuzzObject is data as a JSON object, numbers as json.Number, or nil
// when it isn't one.
func fuzzObject(data []byte) map[string]any {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if dec.Decode(&m) != nil {
		return nil
	}
	return m
}

// signedPayload is sdjwt's Issuer-signed JWT payload, numbers as
// json.Number so they compare as the literals signed.
func signedPayload(t *testing.T, sdjwt string) map[string]any {
	t.Helper()
	issuerJWT, _, _ := strings.Cut(sdjwt, "~")
	parts := strings.Split(issuerJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("issuer JWT has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	payload := fuzzObject(raw)
	if payload == nil {
		t.Fatalf("payload %s isn't a JSON object", raw)
	}
	return payload
}
