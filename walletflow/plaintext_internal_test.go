package walletflow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Copies of a batch must leave the same claims plaintext: one that
// always discloses birthdate, where another makes it selectively
// disclosable, would send what the holder's preview didn't show.
// Per-copy claims and decoys may differ.
func TestSamePlaintext(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(birthdate any, decoys int, exp int64) string {
		t.Helper()
		c, _, err := sdjwtvc.Issue(key, jose.ES256, sdjwtvc.Claims{VCT: "urn:x", Exp: &exp, Additional: map[string]any{"given_name": sdjwtvc.SD("A"), "birthdate": birthdate}}, sdjwtvc.IssueOptions{Decoys: decoys})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	now := time.Now()
	selective := issue(sdjwtvc.SD("1990-01-01"), 0, now.Add(time.Hour).Unix())
	if !samePlaintext(selective, issue(sdjwtvc.SD("1990-01-01"), 3, now.Add(2*time.Hour).Unix())) {
		t.Error("copies differing only in decoys and exp were refused")
	}
	if samePlaintext(selective, issue("1990-01-01", 0, now.Add(time.Hour).Unix())) {
		t.Error("a copy with birthdate plaintext was accepted beside one with it selectively disclosable")
	}
}
