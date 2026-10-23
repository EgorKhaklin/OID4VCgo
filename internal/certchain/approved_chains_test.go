package certchain

import (
	"crypto/x509"
	"errors"
	"slices"
	"testing"
)

// ApprovedChains keeps only the paths a policy approves on its own,
// after it approves them together; with no policy, every path.
func TestApprovedChains(t *testing.T) {
	leaf, approvedAnchor, otherAnchor := &x509.Certificate{Raw: []byte{1}}, &x509.Certificate{Raw: []byte{2}}, &x509.Certificate{Raw: []byte{3}}
	approvedPath, otherPath := []*x509.Certificate{leaf, approvedAnchor}, []*x509.Certificate{leaf, otherAnchor}
	chains := [][]*x509.Certificate{otherPath, approvedPath}
	// Passes when one path ends at approvedAnchor, as EKUInPath passes
	// when one path allows the role.
	anyApproved := func(_ *x509.Certificate, chains [][]*x509.Certificate) error {
		for _, chain := range chains {
			if chain[len(chain)-1] == approvedAnchor {
				return nil
			}
		}
		return errors.New("no approved path")
	}

	got, err := ApprovedChains(leaf, chains, anyApproved)
	if err != nil || len(got) != 1 || !slices.Equal(got[0], approvedPath) {
		t.Errorf("ApprovedChains = %v, %v; want only the approved path", got, err)
	}
	if got, err := ApprovedChains(leaf, chains, nil); err != nil || len(got) != 2 {
		t.Errorf("no policy: %v, %v; want every path", got, err)
	}
	if _, err := ApprovedChains(leaf, [][]*x509.Certificate{otherPath}, anyApproved); err == nil {
		t.Error("no approved path: accepted")
	}
	// A policy that approves each path but not the two together.
	onlyOne := func(_ *x509.Certificate, chains [][]*x509.Certificate) error {
		if len(chains) != 1 {
			return errors.New("more than one path")
		}
		return nil
	}
	if _, err := ApprovedChains(leaf, chains, onlyOne); err == nil {
		t.Error("a policy refusing the paths together: accepted")
	}
	// A policy approving the paths together but none on its own.
	together := func(_ *x509.Certificate, chains [][]*x509.Certificate) error {
		if len(chains) < 2 {
			return errors.New("one path")
		}
		return nil
	}
	if _, err := ApprovedChains(leaf, chains, together); err == nil {
		t.Error("no path approved on its own: accepted")
	}
}
