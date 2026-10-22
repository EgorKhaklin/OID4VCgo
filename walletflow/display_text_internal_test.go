package walletflow

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// An issuer's display text reaches the holder without control, line
// separator or invisible format characters, and bounded, the joiners
// that scripts and emoji need aside; a color only as a plain CSS hex or
// named color.
func TestDisplayText(t *testing.T) {
	for in, want := range map[string]string{
		"Example Bank":                                     "Example Bank",
		"Pay\u202egnp.exe":                                 "Paygnp.exe",
		"line\nbreak\x00":                                  "line break",
		"\u2066Isolated\u2069 \u200fmark\u200e":            "Isolated mark",
		"Bank\u2028Verified by the State\u2029":            "Bank Verified by the State",
		"\ufeffEx\u200bam\u2060ple\u00ad Bank":             "Example Bank",
		"Bank\U000e0041\U000e0042\U000e007f":               "Bank",
		"\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645": "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
		"\U0001f469\u200d\U0001f4bb Coders":                "\U0001f469\u200d\U0001f4bb Coders",
	} {
		if got := displayText(in, maxDisplayName); got != want {
			t.Errorf("displayText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := displayText(strings.Repeat("é", 500), maxDisplayName); utf8.RuneCountInString(got) != maxDisplayName {
		t.Errorf("kept %d runes, want %d", utf8.RuneCountInString(got), maxDisplayName)
	}
	for in, want := range map[string]string{"#12107c": "#12107c", "#FFF": "#FFF", "white": "white", "red; background: url(x)": "", "rgb(1,2,3)": "rgb(1,2,3)", "hsl(120deg 50% 50%)": "hsl(120deg 50% 50%)", "rgb(url(x))": "", "#12": ""} {
		if got := displayColor(in); got != want {
			t.Errorf("displayColor(%q) = %q, want %q", in, got, want)
		}
	}
}
