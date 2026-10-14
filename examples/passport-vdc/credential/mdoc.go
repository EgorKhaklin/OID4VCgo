package credential

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// fullDateTag is CBOR tag 1004, an RFC 8943 full-date string — the
// form ISO/IEC 18013-5 uses for dates like birth_date.
const fullDateTag = 1004

func fullDate(t time.Time) cbor.Tag {
	return cbor.Tag{Number: fullDateTag, Content: t.Format(time.DateOnly)}
}

// MdocClaims encodes e as a Photo ID mdoc (see DocType). DeviceKey is
// left unset: issuer.RequestCredential binds each issued instance to
// the Wallet's own key.
func MdocClaims(e passport.Evidence, o Options) (*mdoc.Claims, error) {
	validUntil, err := ValidUntil(e, o)
	if err != nil {
		return nil, err
	}
	if len(e.File) == 0 {
		return nil, fmt.Errorf("credential: evidence is missing the passport file")
	}

	id := e.Identity
	iso := map[string]interface{}{
		FamilyName:       id.FamilyName,
		GivenName:        id.GivenNames,
		Sex:              isoSex(id.Sex),
		Nationality:      id.Nationality,
		IssuingAuthority: IssuingAuthorityName,
		IssueDate:        fullDate(o.Now),
		ExpiryDate:       fullDate(validUntil),
	}
	if o.IssuingCountry != "" {
		iso[IssuingCountry] = o.IssuingCountry
	}
	if bd, ok := birthDate(id.BirthDate); ok {
		iso[BirthDate] = bd
	}
	if len(e.Portrait) > 0 {
		iso[Portrait] = e.Portrait
	}
	for threshold, over := range ageClaims(e, o) {
		iso[fmt.Sprintf("%s%02d", mdocAgeOverPrefix, threshold)] = over
	}

	return &mdoc.Claims{
		DocType: DocType,
		NameSpaces: map[string]map[string]interface{}{
			ISONamespace:     iso,
			PhotoIDNamespace: {TravelDocumentNumber: id.DocumentNumber},
			DemoNamespace:    {NamesFromMRZ: id.NamesFromMRZ, PassportExpiryDate: fullDate(id.ExpiryDate)},
			FileNamespace:    {PassportFile: e.File},
		},
		Signed:     o.Now,
		ValidFrom:  o.Now,
		ValidUntil: validUntil,
	}, nil
}

// birthDate is ISO/IEC TS 23220-2's birth_date structure (§6.3.1.3),
// always used: the date, and an approximate_mask marking the digits
// that aren't known. An MRZ two-digit year read either way (a child's
// passport without DG11) gives the youngest reading with its century
// masked — so the date never overstates age. There's none for an
// unknown date of birth.
func birthDate(b passport.BirthDate) (map[string]interface{}, bool) {
	switch {
	case b.Known():
		return map[string]interface{}{BirthDate: fullDate(b.Date)}, true
	case b.Resolution == passport.BirthDateAmbiguous && !b.Youngest.IsZero():
		return map[string]interface{}{BirthDate: fullDate(b.Youngest), approximateMask: "11000000"}, true
	default:
		return nil, false
	}
}

// approximateMask is the birth_date structure's mask: 8 digits over
// YYYYMMDD, 1 marking a digit that isn't known.
const approximateMask = "approximate_mask"

// isoSex is the MRZ sex code as ISO/IEC 5218: 1 male, 2 female, and 0
// ("not known") for X or unspecified.
func isoSex(mrz string) uint {
	switch mrz {
	case "M":
		return 1
	case "F":
		return 2
	default:
		return 0
	}
}
