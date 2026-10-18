// Package identifier checks the identifiers a reader or Verifier
// names (an mdoc's docType, namespaces and data elements), which a
// wallet shows the holder on its consent screen.
package identifier

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// MaxLength bounds an identifier, in bytes: real ones are a few dozen.
const MaxLength = 256

// Check refuses an identifier that's empty, too long, not UTF-8, or
// carries a control or bidirectional formatting character: a request
// naming "age_over_18\nRetain: no", or one reversed by U+202E, could
// otherwise forge a line of the consent screen. A real identifier has
// none, so refusing is safer than showing a cleaned copy that no longer
// names what's sent.
func Check(s string) error {
	switch {
	case s == "":
		return fmt.Errorf("an identifier is empty")
	case len(s) > MaxLength:
		return fmt.Errorf("an identifier is %d bytes, over %d", len(s), MaxLength)
	case !utf8.ValidString(s):
		return fmt.Errorf("identifier %q isn't UTF-8", s)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return fmt.Errorf("identifier %q has a control or bidirectional formatting character", s)
		}
	}
	return nil
}
