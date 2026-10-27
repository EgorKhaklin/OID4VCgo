package mdoc

import (
	"crypto/x509"
	"testing"
)

// FuzzIssuerAuthStatus reads an MSO's status and x5chain out of an
// arbitrary IssuerAuth, unverified as a stored credential's is, and
// derives the status signer's trust from whatever comes out: none of it
// may panic, whatever the IssuerAuth's headers and MSO hold.
func FuzzIssuerAuthStatus(f *testing.F) {
	_, seed, _ := issueFuzzSeed(f, nil)
	f.Add(seed.IssuerAuth)
	f.Add([]byte{0x84, 0x40, 0xa0, 0xf6, 0x40})
	f.Fuzz(func(t *testing.T, issuerAuth []byte) {
		status, chain, err := IssuerAuthStatus(IssuerSigned{IssuerAuth: issuerAuth})
		if err != nil {
			return
		}
		var il *IdentifierListRef
		var sl *StatusListRef
		if status != nil {
			il, sl = status.IdentifierList, status.StatusList
		}
		if trust, err := IdentifierListTrust(il, chain); err == nil && trust.LeafPolicy != nil && len(chain) > 0 {
			_ = trust.LeafPolicy(chain[0], [][]*x509.Certificate{chain})
		}
		_, _ = StatusTrust(sl, chain)
	})
}
