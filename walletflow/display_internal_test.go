package walletflow

import (
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// Only a logo an app may load is kept: https, or a data: image.
func TestLogoOf(t *testing.T) {
	for uri, keep := range map[string]bool{
		"https://issuer.example/logo.png":    true,
		"data:image/png;base64,iVBORw0KGgo=": true,
		"http://issuer.example/logo.png":     false,
		"data:text/html;base64,PHNjcmlwdD4=": false,
		"data:image/svg+xml;base64,PHN2Zz4=": false,
		"data:IMAGE/SVG+XML,<svg/>":          false,
		"javascript:alert(1)":                false,
		"org.example.app:/logo":              false,
		"https:///no-host":                   false,
		"https://issuer.example./logo.png":   true,
		"https://cdn1.issuer.example/l.png":  true,
		// An IP address or localhost: the phone's own network.
		"https://127.0.0.1/logo.png":        false,
		"https://192.168.1.1:8443/logo.png": false,
		"https://[::1]/logo.png":            false,
		"https://[fe80::1%25en0]/logo.png":  false,
		"https://localhost/logo.png":        false,
		"https://LOCALHOST./logo.png":       false,
		"https://printer.localhost/l.png":   false,
		"https://2130706433/logo.png":       false,
		"https://0x7f.1/logo.png":           false,
		"https://10.0.0.010/logo.png":       false,
		"https://[::ffff:7f00:1]/logo.png":  false,
		// A single label or a local-only domain: names the phone's own
		// network resolves.
		"https://router/logo.png":             false,
		"https://router./logo.png":            false,
		"https://printer.local/logo.png":      false,
		"https://PRINTER.LOCAL./logo.png":     false,
		"https://nas.home.arpa/logo.png":      false,
		"https://home.arpa/logo.png":          false,
		"https://svc.corp.internal/logo.png":  false,
		"https://nas.lan/logo.png":            false,
		"https://lan/logo.png":                false,
		"https://issuer.local.example/l.png":  true,
		"https://issuer.lan.example/l.png":    true,
		"https://internal.issuer.example/l.p": true,
	} {
		if got := logoOf(&oid4vci.Logo{URI: uri}) != nil; got != keep {
			t.Errorf("logoOf(%q) kept = %v, want %v", uri, got, keep)
		}
	}
}

func TestBestLocale(t *testing.T) {
	locales := []string{"en", "de", ""}
	at := func(i int) string { return locales[i] }
	for prefs, want := range map[string]int{"de-AT": 1, "EN": 0, "fr": 2, "": 2} {
		var p []string
		if prefs != "" {
			p = []string{prefs}
		}
		if got := bestLocale(len(locales), at, p); got != want {
			t.Errorf("bestLocale(%q) = %d, want %d", prefs, got, want)
		}
	}
	if bestLocale(0, at, nil) != -1 {
		t.Error("no entries: want -1")
	}
}
