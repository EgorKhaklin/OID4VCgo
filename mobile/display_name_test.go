package mobile

import "testing"

// A certificate's name reaches the holder's screen without control or
// bidirectional formatting characters, bounded.
func TestDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"State Police":            "State Police",
		"State‮ Police":      "State Police",
		"Reader\nTrusted: yes":    "ReaderTrusted: yes",
		"  ⁦Isolated⁩ ": "Isolated",
	} {
		if got := displayName(in); got != want {
			t.Errorf("displayName(%q) = %q, want %q", in, got, want)
		}
	}
}
