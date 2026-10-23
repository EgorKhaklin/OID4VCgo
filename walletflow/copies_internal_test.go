package walletflow

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Copies of one credential may differ in what makes each a separate
// copy (validity, holder key, status entry, ID, pseudonymous subject),
// but not in what the holder is shown.
func TestSameHolderClaims(t *testing.T) {
	base := map[string]any{"vct": "pid", "given_name": "Alice", "age_over_18": true, "iat": 1.0, "cnf": map[string]any{"jwk": "a"}, "status": map[string]any{"idx": 1.0}}
	perCopy := map[string]any{"vct": "pid", "given_name": "Alice", "age_over_18": true, "iat": 2.0, "cnf": map[string]any{"jwk": "b"}, "status": map[string]any{"idx": 2.0}, "sub": "p2"}
	if !sameHolderClaims(base, perCopy) {
		t.Error("copies differing only per copy were refused")
	}
	for name, other := range map[string]map[string]any{
		"another name":  {"vct": "pid", "given_name": "Mallory", "age_over_18": true},
		"a claim fewer": {"vct": "pid", "given_name": "Alice"},
		"a claim more":  {"vct": "pid", "given_name": "Alice", "age_over_18": true, "birthdate": "2000-01-01"},
		"another type":  {"vct": "other", "given_name": "Alice", "age_over_18": true},
	} {
		if sameHolderClaims(base, other) {
			t.Errorf("%s: accepted", name)
		}
	}
	mdoc := map[string]any{"org.iso.18013.5.1": map[string]any{"family_name": "Doe"}}
	if sameHolderClaims(mdoc, map[string]any{"org.iso.18013.5.1": map[string]any{"family_name": "Roe"}}) {
		t.Error("mdoc copies with different elements accepted")
	}
}

// Copies sharing an SD-JWT VC's jti or sub, or a status list entry (an
// mdoc's too), are correlated; differing ones, and a jti in an mdoc's
// claims, aren't.
func TestCopiesCorrelated_Detection(t *testing.T) {
	ref := func(idx uint64) *statuslist.StatusListRef {
		return &statuslist.StatusListRef{URI: "https://status.example/1", Idx: idx}
	}
	two := func(a, b *statuslist.StatusListRef) []CredentialCopy {
		return []CredentialCopy{{StatusList: a}, {StatusList: b}}
	}
	for name, tc := range map[string]struct {
		format string
		copies []CredentialCopy
		claims []map[string]any
		want   bool
	}{
		"distinct":           {"dc+sd-jwt", two(ref(1), ref(2)), []map[string]any{{"jti": "a", "sub": "x"}, {"jti": "b", "sub": "y"}}, false},
		"one jti":            {"dc+sd-jwt", two(ref(1), ref(2)), []map[string]any{{"jti": "a"}, {"jti": "a"}}, true},
		"one sub":            {"dc+sd-jwt", two(nil, nil), []map[string]any{{"sub": "x"}, {"sub": "x"}}, true},
		"one status entry":   {"dc+sd-jwt", two(ref(1), ref(1)), []map[string]any{{}, {}}, true},
		"mdoc status entry":  {"mso_mdoc", two(ref(3), ref(3)), []map[string]any{{}, {}}, true},
		"mdoc namespace jti": {"mso_mdoc", two(nil, nil), []map[string]any{{"jti": "a"}, {"jti": "a"}}, false},
		"one copy":           {"dc+sd-jwt", []CredentialCopy{{StatusList: ref(1)}}, []map[string]any{{"jti": "a"}}, false},
	} {
		if got := copiesCorrelated(tc.format, tc.copies, tc.claims); got != tc.want {
			t.Errorf("%s: copiesCorrelated = %v, want %v", name, got, tc.want)
		}
	}
}

// Copies sharing a disclosure digest, or a validity timestamp to the
// second, are correlated: every Verifier receives those. A timestamp
// rounded to the day isn't counted, nor are copies differing in both.
func TestCopiesCorrelated_DigestsAndTimestamps(t *testing.T) {
	ca, caKey := testcert.CA(t, "correlation test CA")
	leaf, leafKey := testcert.Leaf(t, "correlation test issuer", ca, caKey)
	now := time.Now()
	sdjwt := func(nbf, exp int64) string {
		t.Helper()
		c, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
			VCT: "urn:x", Nbf: &nbf, Exp: &exp,
			Additional: map[string]any{"given_name": sdjwtvc.SD("Alice"), "nationalities": []any{sdjwtvc.SDElement("DE")}},
		}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	day := now.UTC().Truncate(24 * time.Hour).Unix()
	exp := sdjwtvc.RoundedExp(now, 48*time.Hour)
	precise := now.Unix()
	reused := sdjwt(day, exp)
	mdocCopy := func(signed time.Time) string {
		t.Helper()
		f := testmdoc.IssueWith(t, func(c *mdoc.Claims) {
			c.Signed, c.ValidFrom, c.ValidUntil = signed, signed, signed.Add(time.Hour)
		})
		raw, err := f.IssuerSigned.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	at := now.Truncate(time.Second)
	sharedMdoc := mdocCopy(at.Add(time.Second))
	for name, tc := range map[string]struct {
		format string
		a, b   string
		want   bool
	}{
		"sd-jwt, rounded to the day": {"dc+sd-jwt", sdjwt(day, exp), sdjwt(day, exp), false},
		"sd-jwt, one precise nbf":    {"dc+sd-jwt", sdjwt(precise, exp), sdjwt(precise, exp), true},
		"sd-jwt, distinct precise":   {"dc+sd-jwt", sdjwt(precise, exp), sdjwt(precise+1, exp), false},
		"sd-jwt, reused disclosures": {"dc+sd-jwt", reused, reused, true},
		"mdoc, one precise signed":   {"mso_mdoc", mdocCopy(at), mdocCopy(at), true},
		"mdoc, distinct precise":     {"mso_mdoc", mdocCopy(at), mdocCopy(at.Add(-time.Second)), false},
		"mdoc, reused value digests": {"mso_mdoc", sharedMdoc, sharedMdoc, true},
		"unreadable copies":          {"dc+sd-jwt", "x", "x", false},
	} {
		copies := []CredentialCopy{{Credential: tc.a}, {Credential: tc.b}}
		if got := copiesCorrelated(tc.format, copies, []map[string]any{{}, {}}); got != tc.want {
			t.Errorf("%s: copiesCorrelated = %v, want %v", name, got, tc.want)
		}
	}
}
