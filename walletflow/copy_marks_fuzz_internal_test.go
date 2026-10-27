package walletflow

import (
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
)

// FuzzCopyMarks checks mdocMarks and sdjwtvcMarks never panic on a
// stored credential, however malformed — they read copies verifyCopy
// checked, but run on every refresh and receipt — and that a copy
// always shares its marks with itself when it has any.
func FuzzCopyMarks(f *testing.F) {
	fixture := testmdoc.IssueWith(f, func(c *mdoc.Claims) {
		c.IdentifierList = &mdoc.IdentifierListRef{ID: []byte{1, 2}, URI: "https://status.example/ids"}
	})
	raw, err := fixture.IssuerSigned.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(base64.RawURLEncoding.EncodeToString(raw))
	f.Add("")
	f.Add("oA")
	f.Add("eyJhbGciOiJFUzI1NiJ9.e30.c2ln~WyJzIiwibiIsInYiXQ~")
	f.Fuzz(func(t *testing.T, credential string) {
		for _, m := range []copyMarks{mdocMarks(credential), sdjwtvcMarks(credential)} {
			if len(m.digests)+len(m.entries)+len(m.times) > 0 && !marksShared([]copyMarks{m, m}) {
				t.Fatalf("%q: a copy's marks aren't shared with themselves", credential)
			}
		}
	})
}
