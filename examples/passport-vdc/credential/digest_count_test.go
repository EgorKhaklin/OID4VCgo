package credential

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// born is adult() with an exactly known date of birth.
func born(day string) passport.Evidence {
	e := adult()
	e.Identity.BirthDate = passport.BirthDate{Resolution: passport.BirthDateExact, Date: date(day), Youngest: date(day)}
	return e
}

// isoDigests is how many digests the issued mdoc's MSO, which every
// reader receives in full, lists for the ISO namespace.
func isoDigests(t *testing.T, e passport.Evidence) int {
	t.Helper()
	claims, err := MdocClaims(e, Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	signed, _ := issueAndVerifyMdocSigned(t, claims)
	mso, err := mdoc.IssuerAuthMSO(signed)
	if err != nil {
		t.Fatal(err)
	}
	return len(mso.ValueDigests[ISONamespace])
}

// ageDigests is how many digests the issued SD-JWT VC's
// age_equal_or_over object lists in its _sd array, which is in the
// Issuer-signed payload every verifier receives.
func ageDigests(t *testing.T, e passport.Evidence) int {
	t.Helper()
	claims, err := SDJWTClaims(e, testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	sdjwt, _ := issueAndVerifySDJWTSigned(t, claims)
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(strings.SplitN(sdjwt, "~", 2)[0], ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Ages struct {
			SD []string `json:"_sd"`
		} `json:"age_equal_or_over"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	return len(payload.Ages.SD)
}

// TestDigestCountsDontRevealOmittedAgeClaims: an age claim the holder
// crosses within the validity period is left out (ageClaims), but the
// number of digests every verifier sees stays the same — the mdoc's
// ISO namespace and the SD-JWT VC's age_equal_or_over object both have
// a decoy in its place — so it doesn't say the holder is about to turn
// 13, 16, 18, 21 or 65.
func TestDigestCountsDontRevealOmittedAgeClaims(t *testing.T) {
	holders := map[string]passport.Evidence{
		"born 1980, no threshold near":       born("1980-01-01"),
		"born 2000, no threshold near":       born("2000-01-20"),
		"turns 18 in four months":            born("2009-01-20"),
		"turns 13 in two months":             born("2013-12-01"),
		"turns 65 next month":                born("1961-10-20"),
		"ambiguous MRZ year, turns 13 later": child(),
	}
	omitted := 0
	isoCounts := map[int][]string{}
	for name, e := range holders {
		until, err := ValidUntil(e, Options{Now: now})
		if err != nil {
			t.Fatal(err)
		}
		omitted += len(DefaultAgeThresholds) - len(ageClaims(e, Options{Now: now}, until))
		n := isoDigests(t, e)
		isoCounts[n] = append(isoCounts[n], name)
		if got := ageDigests(t, e); got != len(DefaultAgeThresholds) {
			t.Errorf("%s: age_equal_or_over has %d digests, want %d, one per threshold", name, got, len(DefaultAgeThresholds))
		}
	}
	if omitted == 0 {
		t.Fatal("no holder has an age claim left out: the test checks nothing")
	}
	if len(isoCounts) != 1 {
		t.Errorf("the mdoc's ISO namespace digest counts differ between holders: %v", isoCounts)
	}
}
