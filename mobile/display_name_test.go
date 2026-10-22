package mobile

import "testing"

// A certificate's name reaches the holder's screen without control, line
// separator or invisible format characters, bounded.
func TestDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"State Police":             "State Police",
		"State\u202e Police":       "State Police",
		"Reader\nTrusted: yes":     "Reader Trusted: yes",
		"Reader\u2028Trusted: yes": "Reader Trusted: yes",
		"Sta\u200bte Pol\ufeffice": "State Police",
		"  \u2066Isolated\u2069 ":  "Isolated",
	} {
		if got := displayName(in); got != want {
			t.Errorf("displayName(%q) = %q, want %q", in, got, want)
		}
	}
}
