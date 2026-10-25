package mobile

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"

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

	s, err := newCRLSet("crls", crl)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.set(pemOf("CERTIFICATE", ca.Raw)); err == nil {
		t.Error("set took a certificate")
	}
	if got, _ := s.checker().Lists(context.Background()); len(got) != 1 {
		t.Errorf("after a refused set, %d lists, want the 1 kept", len(got))
	}
	if _, err := newCRLSet("crls", "not PEM"); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "crls") {
		t.Errorf("newCRLSet: %v, want invalid_input naming crls", err)
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
