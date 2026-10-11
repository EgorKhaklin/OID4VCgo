package issuer_test

import (
	"context"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// A deferred credential's notification_id is bound to its holder, as an
// immediate one's is: another holder of the same wallet solution (the
// same client_id) can't send events for it.
func TestDeferredNotificationID_BoundToSubject(t *testing.T) {
	f := newDeferralFixture(t)
	ctx := context.Background()
	txID, _ := f.deferOne(t)
	if err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()}); err != nil {
		t.Fatal(err)
	}
	res, err := f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID})
	if err != nil || res.NotificationID == "" {
		t.Fatalf("RequestDeferredCredential = %+v, %v", res, err)
	}
	other := deferralAuth
	other.Subject = deferralAuth.Subject + "-other"
	if err := f.iss.RequestNotification(ctx, other, issuer.NotificationRequest{NotificationID: res.NotificationID, Event: oid4vci.NotificationEventCredentialDeleted}); err == nil {
		t.Error("another holder of the same client sent an event for the deferred credential")
	}
	if err := f.iss.RequestNotification(ctx, deferralAuth, issuer.NotificationRequest{NotificationID: res.NotificationID, Event: oid4vci.NotificationEventCredentialAccepted}); err != nil {
		t.Errorf("the holder's own event: %v", err)
	}
}
