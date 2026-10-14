package mobile

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// oidExtKeyUsage is the extended key usage extension's OID (RFC 5280
// §4.2.1.12).
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// parseOID parses a dotted object identifier, such as "1.3.6.1.5.5.7.3.2".
func parseOID(dotted string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(dotted, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%q isn't a dotted object identifier", dotted)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%q isn't a dotted object identifier", dotted)
		}
		oid[i] = n
	}
	return oid, nil
}

// requireEKU is a leaf policy refusing a certificate whose extended key
// usage extension doesn't list oid: the role an ecosystem marks its
// verifiers' or registrars' certificates with. It reads the extension
// itself, so a standard key usage and a private one match alike.
func requireEKU(oid asn1.ObjectIdentifier) func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
	return func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		for _, ext := range leaf.Extensions {
			if !ext.Id.Equal(oidExtKeyUsage) {
				continue
			}
			var usages []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &usages); err != nil {
				return fmt.Errorf("the certificate's extended key usage: %w", err)
			}
			if slices.ContainsFunc(usages, oid.Equal) {
				return nil
			}
		}
		return fmt.Errorf("the certificate's extended key usage doesn't include %s", oid)
	}
}

// pemCertificates are the DER certificates in pemText.
func pemCertificates(pemText string) [][]byte {
	var out [][]byte
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
}

// checkRoleRoots refuses, outside development, verifier or registrar
// roots that share a trust anchor with another role's without an
// extended key usage to tell that role's certificates apart: otherwise
// an issuer's signing certificate, say, would be taken for a trusted
// Verifier, or a Verifier's second certificate for a registrar.
func checkRoleRoots(cfg config) error {
	if cfg.Development {
		return nil
	}
	roles := []struct {
		name, roots string
		eku         string
	}{
		{"verifier_roots", cfg.VerifierRoots, cfg.VerifierRequireEKU},
		{"registrar_roots", cfg.RegistrarRoots, cfg.RegistrarRequireEKU},
		{"issuer_roots", cfg.IssuerRoots, "-"},
		{"mdoc_reader_roots", cfg.MdocReaderRoots, boolEKU(cfg.MdocReaderRequireEKU)},
	}
	for i, a := range roles[:2] {
		if a.eku != "" {
			continue
		}
		for j, b := range roles {
			if i == j || !shareAnchor(a.roots, b.roots) {
				continue
			}
			return newError(CodeInvalidInput, fmt.Errorf("%s shares a trust anchor with %s: set %s to tell its certificates apart", a.name, b.name, strings.TrimSuffix(a.name, "_roots")+"_require_eku"))
		}
	}
	return nil
}

func boolEKU(set bool) string {
	if set {
		return "-"
	}
	return ""
}

func shareAnchor(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	theirs := pemCertificates(b)
	return slices.ContainsFunc(pemCertificates(a), func(der []byte) bool {
		return slices.ContainsFunc(theirs, func(o []byte) bool { return bytes.Equal(der, o) })
	})
}

// roleEKU is the leaf policy for the config key name's OID, nil if
// it's unset.
func roleEKU(name, dotted string) (func(*x509.Certificate, [][]*x509.Certificate) error, error) {
	if dotted == "" {
		return nil, nil
	}
	oid, err := parseOID(dotted)
	if err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("%s: %w", name, err))
	}
	return requireEKU(oid), nil
}
