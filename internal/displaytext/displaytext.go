// Package displaytext fits text from another party, such as an issuer's
// display name or a certificate's common name, to show the holder.
package displaytext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Clean is s fit to show the holder: control characters and line and
// paragraph separators become spaces, so the text stays on the lines
// the app gives it, format characters are dropped, and at most limit
// runes are kept, trimmed of surrounding space. Format characters (Cf)
// are invisible: the bidirectional formatting ones can make text read
// other than it is, and the rest (zero-width space, word joiner, byte
// order mark, soft hyphen, tag characters) can hide text or break it
// where the app doesn't expect. The zero-width joiner and non-joiner
// stay: scripts such as Persian and Devanagari, and emoji sequences,
// need them to render right, and they join or part neighbouring
// characters without hiding or reordering any.
func Clean(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case n == limit:
			return strings.TrimSpace(b.String())
		case r == utf8.RuneError, isHiddenFormat(r):
			continue
		case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// isHiddenFormat reports whether r is a format character (Cf) other than
// the zero-width non-joiner and joiner: among them the bidirectional
// embeddings, overrides, isolates and marks.
func isHiddenFormat(r rune) bool {
	return r != '\u200c' && r != '\u200d' && unicode.Is(unicode.Cf, r)
}
