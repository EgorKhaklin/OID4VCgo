package identifier

import "testing"

func TestCheck(t *testing.T) {
	for s, ok := range map[string]bool{
		"org.iso.18013.5.1":        true,
		"age_over_18":              true,
		"":                         false,
		"age_over_18\nRetain: no":  false,
		"family‮name":         false,
		"⁦isolated⁩":     false,
		"\xff\xfe":                 false,
		string(make([]byte, 300)): false,
	} {
		if err := Check(s); (err == nil) != ok {
			t.Errorf("Check(%q) = %v", s, err)
		}
	}
}
