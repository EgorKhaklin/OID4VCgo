package issuer

import "testing"

// A Content-Type's parameters don't change its media type (RFC 9110
// §8.3.1): an encrypted request sent as "application/jwt;
// charset=utf-8" is still one.
func TestIsMediaType(t *testing.T) {
	for header, want := range map[string]bool{
		"application/jwt":                true,
		"application/jwt; charset=utf-8": true,
		"APPLICATION/JWT":                true,
		"application/json":               false,
		"application/jwt-something":      false,
		"":                               false,
	} {
		if got := isMediaType(header, jweContentType); got != want {
			t.Errorf("isMediaType(%q) = %v, want %v", header, got, want)
		}
	}
}
