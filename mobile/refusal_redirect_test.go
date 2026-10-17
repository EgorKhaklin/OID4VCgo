package mobile

import "testing"

// The refusal's redirect_uri is taken once.
func TestTakeRefusalRedirect(t *testing.T) {
	w := &Wallet{refusalRedirect: "https://verifier.example/done"}
	if got := w.TakeRefusalRedirect(); got != "https://verifier.example/done" {
		t.Errorf("first take = %q", got)
	}
	if got := w.TakeRefusalRedirect(); got != "" {
		t.Errorf("second take = %q, want none", got)
	}
}
