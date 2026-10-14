package issuer_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The offer's tx_code comes from the stored record's Transaction Code,
// so the PIN the Wallet asks for is the one redemption checks; the code
// is generated, 256 bits.
func TestCreatePreAuthorizedOffer(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
		cfg.Limits.MaxDPoPProofAge = 0
		deps.DPoPReplay = nil
	})
	ctx := context.Background()
	verified := &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"}

	result, err := f.iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"},
		CredentialIdentifiers: true, Subject: "holder-1", TxCode: "4821", TxCodeDescription: "sent by SMS",
		Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("CreatePreAuthorizedOffer: %v", err)
	}
	grant := result.Offer.Grants.PreAuthorizedCode
	if grant == nil || len(grant.PreAuthorizedCode) != 43 {
		t.Fatalf("grant = %+v, want a 256-bit code", grant)
	}
	if tx := grant.TxCode; tx == nil || tx.InputMode != oid4vci.TxCodeInputModeNumeric || tx.Length != 4 || tx.Description != "sent by SMS" {
		t.Errorf("tx_code = %+v, want numeric, 4 digits, the description", tx)
	}
	if result.URI == "" {
		t.Error("no offer URI")
	}
	redeem := func(code, txCode string) (issuer.RedeemedPreAuthorizedCode, error) {
		return f.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: code, TxCode: txCode, Verified: verified})
	}
	if _, err := redeem(grant.PreAuthorizedCode, ""); err == nil {
		t.Error("redeemed without the Transaction Code the offer asks for")
	}
	got, err := redeem(grant.PreAuthorizedCode, "4821")
	if err != nil {
		t.Fatalf("redeem with the Transaction Code: %v", err)
	}
	if got.Subject != "holder-1" || len(got.AuthorizationDetails) != 1 || got.Scope[0] != "identity_credential" {
		t.Errorf("redeemed %+v", got)
	}

	// Without a Transaction Code the offer has no tx_code object, and
	// the code redeems without one.
	plain, err := f.iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, Scopes: []string{"identity_credential"}, Lifetime: time.Minute,
	})
	if err != nil || plain.Offer.Grants.PreAuthorizedCode.TxCode != nil {
		t.Fatalf("offer without a Transaction Code = %+v, %v", plain.Offer.Grants, err)
	}
	if _, err := redeem(plain.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode, ""); err != nil {
		t.Errorf("redeem without a Transaction Code: %v", err)
	}
	if text, err := f.iss.CreatePreAuthorizedOffer(ctx, issuer.CreatePreAuthorizedOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"}, TxCode: "ab12", Lifetime: time.Minute,
	}); err != nil || text.Offer.Grants.PreAuthorizedCode.TxCode.InputMode != oid4vci.TxCodeInputModeText {
		t.Errorf("an alphanumeric Transaction Code: %+v, %v", text.Offer.Grants, err)
	}

	for name, req := range map[string]issuer.CreatePreAuthorizedOfferRequest{
		"no configurations":           {Lifetime: time.Minute},
		"no lifetime":                 {CredentialConfigurationIDs: []string{"IdentityCredential"}},
		"description without tx_code": {CredentialConfigurationIDs: []string{"IdentityCredential"}, Lifetime: time.Minute, TxCodeDescription: "x"},
		"unknown configuration":       {CredentialConfigurationIDs: []string{"Nope"}, Lifetime: time.Minute},
	} {
		if _, err := f.iss.CreatePreAuthorizedOffer(ctx, req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
