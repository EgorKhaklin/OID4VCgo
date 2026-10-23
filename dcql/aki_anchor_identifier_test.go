package dcql_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// rootDeclaring is a self-signed trust anchor for key declaring ski as
// its Subject Key Identifier; nil ski lets crypto/x509 derive it.
func rootDeclaring(t *testing.T, name string, key *ecdsa.PrivateKey, ski []byte) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A second trusted root declaring the wanted root's Subject Key
// Identifier doesn't pass the wanted root's "aki" filter: with Roots an
// anchor matches by the identifiers derived from its key, and Anchors
// holding both is a conflict, refused.
func TestAKITrustedAuthoritiesChecker_RejectsSpoofedAnchorSKI(t *testing.T) {
	wanted := rootDeclaring(t, "wanted root", newKey(t), nil)
	spoofKey := newKey(t)
	spoof := rootDeclaring(t, "spoofing root", spoofKey, wanted.SubjectKeyId)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "spoofing root's issuer"}},
		&newKey(t).PublicKey, spoof, spoofKey, nil)
	chain := [][]byte{leaf.Raw}

	roots := dcql.AKITrustedAuthoritiesChecker{Roots: pool(wanted, spoof)}
	if err := roots.CheckTrustedAuthorities(context.Background(), verifiedAKI(wanted), chain); err == nil {
		t.Error("Roots: a root declaring the wanted root's identifier passed its filter")
	}
	anchors := dcql.AKITrustedAuthoritiesChecker{Anchors: []*x509.Certificate{wanted, spoof}}
	if err := anchors.Validate(); err == nil || !strings.Contains(err.Error(), "both claim") {
		t.Errorf("Validate = %v, want the conflict reported", err)
	}
	if err := anchors.CheckTrustedAuthorities(context.Background(), verifiedAKI(wanted), chain); err == nil {
		t.Error("Anchors: a root declaring the wanted root's identifier passed its filter")
	}
}

// An anchor whose Subject Key Identifier isn't derived from its key
// matches by it only from Anchors, where it's unambiguous.
func TestAKITrustedAuthoritiesChecker_AnchorDeclaredSKI(t *testing.T) {
	key := newKey(t)
	root := rootDeclaring(t, "root with its own identifier scheme", key, []byte{1, 2, 3, 4})
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "issuer"}},
		&newKey(t).PublicKey, root, key, nil)
	chain := [][]byte{leaf.Raw}
	other := rootDeclaring(t, "another root", newKey(t), nil)

	if err := (dcql.AKITrustedAuthoritiesChecker{Roots: pool(root)}).CheckTrustedAuthorities(context.Background(), verifiedAKI(root), chain); err == nil {
		t.Error("Roots: a declared identifier not derived from the anchor's key matched")
	}
	anchors := dcql.AKITrustedAuthoritiesChecker{Anchors: []*x509.Certificate{root, other}}
	if err := anchors.CheckTrustedAuthorities(context.Background(), verifiedAKI(root), chain); err != nil {
		t.Errorf("Anchors: the anchor's unambiguous declared identifier didn't match: %v", err)
	}
	if err := anchors.CheckTrustedAuthorities(context.Background(), verifiedAKI(other), chain); err == nil {
		t.Error("Anchors: another anchor's identifier matched")
	}
	// The same key reissued under the same identifier isn't a conflict.
	reissued := rootDeclaring(t, "root with its own identifier scheme, reissued", key, []byte{1, 2, 3, 4})
	if err := (dcql.AKITrustedAuthoritiesChecker{Anchors: []*x509.Certificate{root, reissued}}).Validate(); err != nil {
		t.Errorf("a reissued anchor: %v", err)
	}
}

// Validate refuses both Roots and Anchors, and a nil anchor.
func TestAKITrustedAuthoritiesChecker_Validate(t *testing.T) {
	root := rootDeclaring(t, "root", newKey(t), nil)
	for name, c := range map[string]dcql.AKITrustedAuthoritiesChecker{
		"Roots and Anchors": {Roots: pool(root), Anchors: []*x509.Certificate{root}},
		"a nil anchor":      {Anchors: []*x509.Certificate{root, nil}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, c := range map[string]dcql.AKITrustedAuthoritiesChecker{
		"none":    {},
		"Roots":   {Roots: pool(root)},
		"Anchors": {Anchors: []*x509.Certificate{root}},
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
