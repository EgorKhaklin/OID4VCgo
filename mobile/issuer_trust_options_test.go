package mobile

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// The issuer trust options reach walletflow.Config, and the metadata
// requirements need their roots.
func TestWalletflowConfig_IssuerTrustOptions(t *testing.T) {
	ca, _ := testcert.CA(t, "metadata root")
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	wcfg, err := walletConfig(config{
		Development: true, RequireIssuerName: true, IssuerMetadataRoots: roots,
		RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true, MaxIssuerMetadataAgeSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !wcfg.RequireIssuerName || wcfg.IssuerMetadataRoots == nil || !wcfg.RequireSignedIssuerMetadata ||
		!wcfg.RequireIssuerMetadataName || wcfg.MaxIssuerMetadataAge != time.Hour {
		t.Errorf("walletflow.Config = %+v", wcfg)
	}
	for name, cfg := range map[string]config{
		"signed metadata required without roots": {Development: true, RequireSignedIssuerMetadata: true},
		"a name required without roots":          {Development: true, RequireIssuerMetadataName: true},
		"a negative max age":                     {Development: true, MaxIssuerMetadataAgeSeconds: -1},
		"roots that aren't PEM":                  {Development: true, IssuerMetadataRoots: "not PEM"},
	} {
		if _, err := walletConfig(cfg); err == nil || !strings.Contains(err.Error(), "issuer_metadata") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}
