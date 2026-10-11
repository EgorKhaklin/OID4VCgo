package walletflow

import "testing"

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
