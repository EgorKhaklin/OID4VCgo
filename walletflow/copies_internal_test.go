package walletflow

import (
	"testing"

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
