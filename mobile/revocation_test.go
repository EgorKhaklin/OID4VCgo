package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func pemOf(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// "crls" takes PEM X509 CRL blocks and nothing else, and SetCRLs
// replaces the lists only with ones that parse.
func TestCRLs_Parse(t *testing.T) {
	ca, caKey := testcert.CA(t, "revocation test CA")
	list := testcert.CRL(t, ca, caKey)
	crl := pemOf("X509 CRL", list.Raw)

	for name, text := range map[string]string{"empty": "", "one": crl, "two": crl + "\n" + crl} {
		if _, err := parseCRLs(text); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"a certificate":      pemOf("CERTIFICATE", ca.Raw),
		"a CRL and a cert":   crl + pemOf("CERTIFICATE", ca.Raw),
		"not PEM":            "not PEM",
		"trailing text":      crl + "trailing",
		"a CRL that's junk":  pemOf("X509 CRL", []byte{0x30, 0x00}),
		"too many":           strings.Repeat(crl, maxCRLs+1),
		"a truncated header": "-----BEGIN X509 CRL-----\n",
	} {
		if _, err := parseCRLs(text); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}

	s, err := newCRLSet(crl, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.set(pemOf("CERTIFICATE", ca.Raw)); err == nil {
		t.Error("set took a certificate")
	}
	if got, _ := s.checker().Lists(context.Background()); len(got) != 1 {
		t.Errorf("after a refused set, %d lists, want the 1 kept", len(got))
	}
	if _, err := newCRLSet("not PEM", ""); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "crls") {
		t.Errorf("newCRLSet: %v, want invalid_input naming crls", err)
	}
}

// A leaf pinned in verifier_roots, with "verifier" in "revocation", is
// checked against its CA's CRL, verified with the CA's certificate from
// "crl_issuers": without it, it fails closed; with it, it passes until
// the CRL lists it.
func TestCRLIssuers_PinnedLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "verifier CA")
	leaf, _ := testcert.Leaf(t, "pinned verifier", ca, caKey)
	check := func(crl *x509.RevocationList, issuers string) error {
		t.Helper()
		cfg := config{Development: true, VerifierRoots: pemOf("CERTIFICATE", leaf.Raw),
			CRLs: pemOf("X509 CRL", crl.Raw), CRLIssuers: issuers, Revocation: []string{"verifier"}}
		wcfg, err := walletConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := walletRevocation(cfg, &wcfg); err != nil {
			t.Fatal(err)
		}
		vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots)
		return vt.Revocation.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{leaf}})
	}
	issuers := pemOf("CERTIFICATE", ca.Raw)
	if err := check(testcert.CRL(t, ca, caKey), ""); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
		t.Errorf("without crl_issuers: %v, want ErrNoCurrentCRL", err)
	}
	if err := check(testcert.CRL(t, ca, caKey), issuers); err != nil {
		t.Errorf("with crl_issuers: %v", err)
	}
	if err := check(testcert.CRL(t, ca, caKey, leaf.SerialNumber), issuers); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked, with crl_issuers: %v, want ErrRevoked", err)
	}

	// NewWallet takes the key; it holds CA certificates and nothing else.
	keys, creds := &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}
	if _, err := NewWallet(`{"development":true,"crl_issuers":`+jsonString(issuers)+`}`, keys, creds, nil); err != nil {
		t.Errorf("NewWallet with crl_issuers: %v", err)
	}
	for name, text := range map[string]string{
		"a leaf":        pemOf("CERTIFICATE", leaf.Raw),
		"a CRL":         pemOf("X509 CRL", testcert.CRL(t, ca, caKey).Raw),
		"trailing text": issuers + "trailing",
		"too many":      strings.Repeat(issuers, maxCRLs+1),
	} {
		if _, err := NewWallet(`{"development":true,"crl_issuers":`+jsonString(text)+`}`, keys, creds, nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "crl_issuers") {
			t.Errorf("crl_issuers %s: %v, want invalid_input naming crl_issuers", name, err)
		}
	}
	if _, err := NewProximityReader(`{"issuer_roots":`+jsonString(issuers)+`,"crl_issuers":`+jsonString(pemOf("CERTIFICATE", leaf.Raw))+`}`, nil); code(err) != CodeInvalidInput {
		t.Errorf("a reader's crl_issuers with a leaf: %v, want invalid_input", err)
	}
}

// "revocation" sets each role it names, over the same lists, and
// refuses a role it doesn't know or names twice.
func TestWalletRevocation_Roles(t *testing.T) {
	ca, _ := testcert.CA(t, "verifier root")
	cfg := config{Development: true, VerifierRoots: pemOf("CERTIFICATE", ca.Raw),
		Revocation: []string{"issuer", "issuer_metadata", "registrar", "mdoc_reader", "verifier", "status"}}
	wcfg, err := walletConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walletRevocation(cfg, &wcfg); err != nil {
		t.Fatal(err)
	}
	vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots)
	if wcfg.IssuerRevocation == nil || wcfg.IssuerMetadataRevocation == nil || wcfg.RegistrarRevocation == nil ||
		wcfg.MdocReaderRevocation == nil || wcfg.StatusRevocation == nil || vt.Revocation == nil {
		t.Errorf("a named role has no revocation check: %+v", wcfg)
	}

	cfg.Revocation = []string{"issuer"}
	wcfg, _ = walletConfig(cfg)
	if _, err := walletRevocation(cfg, &wcfg); err != nil {
		t.Fatal(err)
	}
	if vt, _ := wcfg.VerifierTrust.(wallet.X5CVerifierRoots); wcfg.IssuerRevocation == nil || wcfg.StatusRevocation != nil || vt.Revocation != nil {
		t.Error("revocation [issuer] set another role's check, or not the issuer's")
	}

	for name, roles := range map[string][]string{"unknown": {"holder"}, "twice": {"issuer", "issuer"}} {
		cfg.Revocation = roles
		if _, err := walletRevocation(cfg, &wcfg); code(err) != CodeInvalidInput {
			t.Errorf("%s: %v, want invalid_input", name, err)
		}
	}
}

// A reader's "revocation" knows "issuer" and "status" only, and its
// SetCRLs refuses what isn't a CRL.
func TestNewProximityReader_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "IACA")
	roots := pemOf("CERTIFICATE", ca.Raw)
	r, err := NewProximityReader(`{"issuer_roots": `+jsonString(roots)+`, "revocation": ["issuer", "status"]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.statusRevocation == nil {
		t.Error("revocation [status] set no status list check")
	}
	if err := r.SetCRLs(pemOf("X509 CRL", testcert.CRL(t, ca, caKey).Raw)); err != nil {
		t.Errorf("SetCRLs: %v", err)
	}
	if err := r.SetCRLs(roots); code(err) != CodeInvalidInput {
		t.Errorf("SetCRLs(a certificate): %v, want invalid_input", err)
	}
	if _, err := NewProximityReader(`{"issuer_roots": `+jsonString(roots)+`, "revocation": ["verifier"]}`, nil); code(err) != CodeInvalidInput {
		t.Errorf("revocation [verifier] on a reader: %v, want invalid_input", err)
	}
}

func jsonString(s string) string {
	text, _ := marshal(s)
	return text
}
