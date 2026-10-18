package walletflow

import (
	"testing"
	"time"
)

// A copy still valid is presented before an expired one, however the
// two have been used; among valid ones, the first unpresented, then the
// least shown.
func TestNextCopy_PrefersValidCopies(t *testing.T) {
	now := time.Now()
	c := StoredCredential{Copies: []CredentialCopy{
		{HolderKeyID: "expired", ValidUntil: now.Add(-time.Hour)},
		{HolderKeyID: "shown twice", Presented: true, ShownTo: []string{"x", "y"}, ValidUntil: now.Add(time.Hour)},
		{HolderKeyID: "shown once", Presented: true, ShownTo: []string{"x"}, ValidUntil: now.Add(time.Hour)},
	}}
	if _, cp := c.nextCopy(now); cp.HolderKeyID != "shown once" {
		t.Errorf("nextCopy = %q, want the valid copy shown to fewest", cp.HolderKeyID)
	}
	c.Copies = append(c.Copies, CredentialCopy{HolderKeyID: "fresh", ValidUntil: now.Add(time.Hour)})
	if _, cp := c.nextCopy(now); cp.HolderKeyID != "fresh" {
		t.Errorf("nextCopy = %q, want the unpresented valid copy", cp.HolderKeyID)
	}
	// Per Verifier: the copy it saw, unless that one has expired.
	c.Copies[0].ShownTo = []string{"v"}
	if _, cp, reused := c.copyFor(CopyPerVerifier, "v", now); reused || cp.HolderKeyID == "expired" {
		t.Errorf("copyFor = %q (reused %v), want a valid copy instead of the expired one it saw", cp.HolderKeyID, reused)
	}
}
