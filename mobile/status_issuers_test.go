package mobile

import "testing"

// status_issuers reaches walletflow.Config.StatusIssuers.
func TestWalletConfig_StatusIssuers(t *testing.T) {
	want := map[string][]string{"https://issuer.example": {"https://status.example"}}
	wcfg, err := walletConfig(config{Development: true, StatusIssuers: want})
	if err != nil {
		t.Fatal(err)
	}
	if got := wcfg.StatusIssuers["https://issuer.example"]; len(got) != 1 || got[0] != "https://status.example" {
		t.Errorf("StatusIssuers = %v, want %v", wcfg.StatusIssuers, want)
	}
}
