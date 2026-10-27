package certchain

import (
	"crypto/x509"
	"errors"
	"testing"
)

// BothPolicies passes only what both pass, and a nil one passes all.
func TestBothPolicies(t *testing.T) {
	pass := func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("refused") }
	for name, tc := range map[string]struct {
		first, second func(*x509.Certificate, [][]*x509.Certificate) error
		ok            bool
	}{
		"first nil":      {nil, refuse, false},
		"second nil":     {refuse, nil, false},
		"both pass":      {pass, pass, true},
		"second refuses": {pass, refuse, false},
	} {
		if err := BothPolicies(tc.first, tc.second)(nil, nil); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	if BothPolicies(nil, nil) != nil {
		t.Error("BothPolicies(nil, nil) isn't nil")
	}
}
