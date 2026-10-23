package credential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/haip"
)

const testVCT = "https://issuer.example.com/vct/passport/1"

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func date(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

// adult is an adult's passport whose birth year the MRZ alone settles.
func adult() passport.Evidence {
	return passport.Evidence{
		Identity: passport.Identity{
			FamilyName: "DOE", GivenNames: "JANE", NamesFromMRZ: true,
			BirthDate: passport.BirthDate{
				Resolution: passport.BirthDateInferred, Date: date("1980-01-01"), Youngest: date("1980-01-01"),
			},
			Sex: "F", Nationality: "SGP", IssuingCountry: "SGP", DocumentNumber: "K0000000A",
			ExpiryDate: date("2031-01-01"),
		},
		File:     bytes.Repeat([]byte{0xA5}, 20<<10),
		Portrait: testPortrait,
	}
}

// child is a child's passport without DG11: 2014 (12) or 1914 (112).
func child() passport.Evidence {
	e := adult()
	e.Identity.BirthDate = passport.BirthDate{Resolution: passport.BirthDateAmbiguous, Youngest: date("2014-06-15")}
	return e
}

func testIssuer(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "passport-vdc test issuer"},
		NotBefore: today.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return key, der
}

// today is the start of now's UTC day, where every credential issued
// at now starts its validity.
var today = date("2026-09-26")

func TestValidUntil(t *testing.T) {
	cases := []struct {
		name string
		e    passport.Evidence
		o    Options
		want time.Time
	}{
		{name: "default one-year validity", e: adult(), o: Options{Now: now}, want: today.Add(365 * 24 * time.Hour)},
		{
			name: "passport expiry doesn't limit it", e: adult(), o: Options{Now: now, MaxValidity: 10 * 365 * 24 * time.Hour},
			want: today.Add(10 * 365 * 24 * time.Hour),
		},
		// The child turns 13 on 2027-06-15, within the year: that
		// birthday doesn't end the validity.
		{name: "an age threshold doesn't shorten it", e: child(), o: Options{Now: now}, want: today.Add(365 * 24 * time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidUntil(tc.e, tc.o)
			if err != nil {
				t.Fatalf("ValidUntil: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("ValidUntil = %v, want %v", got, tc.want)
			}
		})
	}
	if _, err := ValidUntil(adult(), Options{Now: now, MaxValidity: time.Hour}); !errors.Is(err, ErrNoValidity) {
		t.Errorf("ValidUntil ending before now = %v, want ErrNoValidity", err)
	}
}

// TestValidityDoesNotRevealBirthDate: a 17-year-old's always-disclosed
// exp and MSO validity are the same as anyone's issued that day, so a
// verifier asking only for age_over_16 can't read the date of birth
// from them, nor link copies issued seconds apart.
func TestValidityDoesNotRevealBirthDate(t *testing.T) {
	teen := adult()
	teen.Identity.BirthDate = passport.BirthDate{Resolution: passport.BirthDateExact, Date: date("2009-03-04"), Youngest: date("2009-03-04")}
	later := Options{Now: now.Add(7*time.Hour + 13*time.Second)}
	until := today.Add(365 * 24 * time.Hour)

	for _, o := range []Options{{Now: now}, later} {
		for name, e := range map[string]passport.Evidence{"teen": teen, "adult": adult(), "child": child()} {
			sd, err := SDJWTClaims(e, testVCT, o)
			if err != nil {
				t.Fatalf("%s SDJWTClaims: %v", name, err)
			}
			if *sd.Exp != until.Unix() {
				t.Errorf("%s exp = %v, want %v for everyone issued that day", name, time.Unix(*sd.Exp, 0).UTC(), until)
			}
			md, err := MdocClaims(e, o)
			if err != nil {
				t.Fatalf("%s MdocClaims: %v", name, err)
			}
			if !md.Signed.Equal(today) || !md.ValidFrom.Equal(today) || !md.ValidUntil.Equal(until) {
				t.Errorf("%s MSO signed/validFrom/validUntil = %v/%v/%v, want the day's", name, md.Signed, md.ValidFrom, md.ValidUntil)
			}
		}
	}
}

// TestExpiredPassportStillIssues: an expired passport's data is still
// authentic, so its credential gets the ordinary validity and carries
// the expiry date for a verifier to judge.
func TestExpiredPassportStillIssues(t *testing.T) {
	e := adult()
	e.Identity.ExpiryDate = date("2020-01-01")
	got, err := ValidUntil(e, Options{Now: now})
	if err != nil || !got.Equal(today.Add(365*24*time.Hour)) {
		t.Fatalf("ValidUntil = %v, %v; want the default one-year validity", got, err)
	}
	claims, err := MdocClaims(e, Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	if exp, _ := claims.NameSpaces[DemoNamespace][PassportExpiryDate].(cbor.Tag); exp.Content != "2020-01-01" {
		t.Errorf("passport_expiry_date = %v, want 2020-01-01", claims.NameSpaces[DemoNamespace][PassportExpiryDate])
	}
}

func TestAgeClaimsUseYoungestReading(t *testing.T) {
	until := today.Add(365 * 24 * time.Hour)
	ages := ageClaims(child(), Options{Now: now}, until)
	for threshold, want := range map[int]bool{16: false, 18: false, 21: false, 65: false} {
		if got, ok := ages[threshold]; !ok || got != want {
			t.Errorf("age_over_%d = %v (issued %v), want %v (youngest reading: age 12)", threshold, got, ok, want)
		}
	}
	ages = ageClaims(adult(), Options{Now: now}, until)
	for threshold, want := range map[int]bool{13: true, 18: true, 21: true, 65: false} {
		if ages[threshold] != want {
			t.Errorf("adult age_over_%d = %v, want %v", threshold, ages[threshold], want)
		}
	}
}

// TestAgeClaimsOmitThresholdsCrossedWithinValidity: a false age claim
// that would become wrong before the credential expires isn't issued,
// so the credential needn't expire on that birthday. A true one never
// becomes wrong.
func TestAgeClaimsOmitThresholdsCrossedWithinValidity(t *testing.T) {
	until := today.Add(365 * 24 * time.Hour)
	// The child (youngest reading 2014-06-15) turns 13 on 2027-06-15.
	if v, ok := ageClaims(child(), Options{Now: now}, until)[13]; ok {
		t.Errorf("age_over_13 = %v issued for a holder who turns 13 within the validity", v)
	}
	// Turning 18 the day the credential expires: a minor throughout,
	// so age_over_18 = false stays right.
	e := adult()
	e.Identity.BirthDate = passport.BirthDate{Resolution: passport.BirthDateExact, Date: date("2009-09-27"), Youngest: date("2009-09-27")}
	ages := ageClaims(e, Options{Now: now}, until)
	if v, ok := ages[18]; !ok || v {
		t.Errorf("age_over_18 = %v (issued %v), want false", v, ok)
	}
	if v, ok := ages[16]; !ok || !v {
		t.Errorf("age_over_16 = %v (issued %v), want true", v, ok)
	}
	// Turning 18 the day before it expires: left out.
	e.Identity.BirthDate = passport.BirthDate{Resolution: passport.BirthDateExact, Date: date("2009-09-25"), Youngest: date("2009-09-25")}
	if v, ok := ageClaims(e, Options{Now: now}, until)[18]; ok {
		t.Errorf("age_over_18 = %v issued for a holder who turns 18 within the validity", v)
	}
}

// issueAndVerifyMdoc signs claims as the issuer package would and
// verifies the result, returning the verified namespaces.
func issueAndVerifyMdoc(t *testing.T, claims *mdoc.Claims) map[string]map[string]interface{} {
	t.Helper()
	_, nameSpaces := issueAndVerifyMdocSigned(t, claims)
	return nameSpaces
}

// issueAndVerifyMdocSigned is issueAndVerifyMdoc, also returning the
// IssuerSigned as a holder receives it.
func issueAndVerifyMdocSigned(t *testing.T, claims *mdoc.Claims) (mdoc.IssuerSigned, map[string]map[string]interface{}) {
	t.Helper()
	issuerKey, cert := testIssuer(t)
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	claims.DeviceKey = &deviceKey.PublicKey

	signed, err := mdoc.Issue(issuerKey, haip.RecommendedCOSEAlgorithm, *claims, mdoc.IssueOptions{X5Chain: [][]byte{cert}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	wire, err := signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	verified, err := mdoc.Verify(parsed, DocType, &issuerKey.PublicKey, haip.RecommendedCOSEAlgorithm, mdoc.VerifyOptions{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	return parsed, verified.NameSpaces
}

func TestMdocClaims_Adult(t *testing.T) {
	claims, err := MdocClaims(adult(), Options{Now: now, IssuingCountry: "ZZ"})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	ns := issueAndVerifyMdoc(t, claims)

	identity := ns[ISONamespace]
	if identity[FamilyName] != "DOE" || identity[GivenName] != "JANE" || identity[IssuingAuthority] != IssuingAuthorityName {
		t.Errorf("org.iso.23220.1 = %v", identity)
	}
	// ISO/IEC 5218 sex; the issuer's own country, not the passport's,
	// as issuing_country (what verifiers hold to the document signer);
	// alpha-3 nationality.
	if identity[Sex] != uint64(2) || identity[IssuingCountry] != "ZZ" || identity[Nationality] != "SGP" {
		t.Errorf("sex/issuing_country/nationality = %v/%v/%v, want 2/ZZ/SGP", identity[Sex], identity[IssuingCountry], identity[Nationality])
	}
	none, err := MdocClaims(adult(), Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := none.NameSpaces[ISONamespace][IssuingCountry]; ok {
		t.Error("issuing_country set without Options.IssuingCountry")
	}
	// The mobile document's own issue and expiry dates: the credential's
	// validity, not the passport's.
	if iss, _ := identity[IssueDate].(cbor.Tag); iss.Content != now.Format(time.DateOnly) {
		t.Errorf("issue_date = %v, want %s", identity[IssueDate], now.Format(time.DateOnly))
	}
	if exp, _ := identity[ExpiryDate].(cbor.Tag); exp.Content != "2027-09-26" {
		t.Errorf("expiry_date = %v, want 2027-09-26", identity[ExpiryDate])
	}
	if bd := birthDateOf(t, identity); bd.date != "1980-01-01" || bd.mask != "" {
		t.Errorf("birth_date = %+v, want 1980-01-01 with no mask", bd)
	}
	if ns[PhotoIDNamespace][TravelDocumentNumber] != "K0000000A" {
		t.Errorf("travel_document_number = %v", ns[PhotoIDNamespace][TravelDocumentNumber])
	}
	if ns[DemoNamespace][NamesFromMRZ] != true {
		t.Errorf("names_from_mrz = %v", ns[DemoNamespace][NamesFromMRZ])
	}
	if identity["age_over_18"] != true || identity["age_over_65"] != false {
		t.Errorf("age_over_18/65 = %v/%v", identity["age_over_18"], identity["age_over_65"])
	}

	if got, _ := ns[FileNamespace][PassportFile].([]byte); !bytes.Equal(got, adult().File) {
		t.Error("the passport file did not round-trip byte-for-byte")
	}
}

// A child's ambiguous MRZ birth year is the youngest reading, with its
// century masked (ISO/IEC TS 23220-2's approximate_mask).
func TestMdocClaims_ChildMasksTheCentury(t *testing.T) {
	claims, err := MdocClaims(child(), Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	identity := issueAndVerifyMdoc(t, claims)[ISONamespace]
	if bd := birthDateOf(t, identity); !strings.HasPrefix(bd.date, "2014-") || bd.mask != "11000000" {
		t.Errorf("birth_date = %+v, want the youngest reading with the century masked", bd)
	}
	if identity["age_over_18"] != false {
		t.Errorf("age_over_18 = %v, want false", identity["age_over_18"])
	}
	// The child turns 13 within the validity.
	if v, ok := identity["age_over_13"]; ok {
		t.Errorf("age_over_13 = %v, want it left out", v)
	}
}

// issueAndVerifySDJWT signs claims as the issuer package would and
// verifies the result, returning the fully disclosed payload.
func issueAndVerifySDJWT(t *testing.T, claims *sdjwtvc.Claims) map[string]any {
	t.Helper()
	_, payload := issueAndVerifySDJWTSigned(t, claims)
	return payload
}

// issueAndVerifySDJWTSigned is issueAndVerifySDJWT, also returning the
// issued SD-JWT.
func issueAndVerifySDJWTSigned(t *testing.T, claims *sdjwtvc.Claims) (string, map[string]any) {
	t.Helper()
	issuerKey, _ := testIssuer(t)
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, oid4vci.ES256, *claims, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatalf("sdjwtvc.Issue: %v", err)
	}
	payload, _, err := sdjwtvc.Verify(sdjwt, &issuerKey.PublicKey, oid4vci.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	return sdjwt, payload
}

func TestSDJWTClaims_Adult(t *testing.T) {
	claims, err := SDJWTClaims(adult(), testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	payload := issueAndVerifySDJWT(t, claims)

	if payload["vct"] != testVCT || payload[FamilyName] != "DOE" || payload[SDJWTBirthDate] != "1980-01-01" {
		t.Errorf("payload = %v", payload)
	}
	nats, _ := payload[SDJWTNationalities].([]any)
	if len(nats) != 1 || nats[0] != "SGP" {
		t.Errorf("nationalities = %v", payload[SDJWTNationalities])
	}
	ages, _ := payload[SDJWTAgeEqualOrOver].(map[string]any)
	if ages["18"] != true || ages["65"] != false {
		t.Errorf("age_equal_or_over = %v", ages)
	}
	s, _ := payload[PassportFile].(string)
	if got, err := base64.RawURLEncoding.DecodeString(s); err != nil || !bytes.Equal(got, adult().File) {
		t.Error("the passport file did not round-trip byte-for-byte")
	}
}

func TestSDJWTClaims_ChildOmitsBirthDate(t *testing.T) {
	claims, err := SDJWTClaims(child(), testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	payload := issueAndVerifySDJWT(t, claims)
	if _, ok := payload[SDJWTBirthDate]; ok {
		t.Error("birthdate issued for an ambiguous MRZ birth year")
	}
	ages, _ := payload[SDJWTAgeEqualOrOver].(map[string]any)
	if ages["18"] != false {
		t.Errorf("age_equal_or_over.18 = %v, want false", ages["18"])
	}
	if _, ok := ages["13"]; ok {
		t.Errorf("age_equal_or_over.13 = %v, want it left out: the child turns 13 within the validity", ages["13"])
	}
	if exp, _ := payload["exp"].(float64); int64(exp) != today.Add(365*24*time.Hour).Unix() {
		t.Errorf("exp = %v, want a year from the start of the issuance day, not a birthday", payload["exp"])
	}
}

func TestEncodersRequireThePassportFile(t *testing.T) {
	e := adult()
	e.File = nil
	if _, err := MdocClaims(e, Options{Now: now}); err == nil {
		t.Error("MdocClaims without the passport file = nil error")
	}
	if _, err := SDJWTClaims(e, testVCT, Options{Now: now}); err == nil {
		t.Error("SDJWTClaims without the passport file = nil error")
	}
	if _, err := SDJWTClaims(adult(), "", Options{Now: now}); err == nil {
		t.Error("SDJWTClaims without vct = nil error")
	}
}

type birthDateValue struct{ date, mask string }

// birthDateOf reads ISO/IEC TS 23220-2's birth_date structure.
func birthDateOf(t *testing.T, ns map[string]interface{}) birthDateValue {
	t.Helper()
	raw, err := cbor.Marshal(ns[BirthDate])
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Date cbor.Tag `cbor:"birth_date"`
		Mask string   `cbor:"approximate_mask"`
	}
	if err := cbor.Unmarshal(raw, &v); err != nil {
		t.Fatalf("birth_date %#v isn't the structure: %v", ns[BirthDate], err)
	}
	if v.Date.Number != fullDateTag {
		t.Errorf("birth_date's date is tag %d, want %d", v.Date.Number, fullDateTag)
	}
	s, _ := v.Date.Content.(string)
	return birthDateValue{date: s, mask: v.Mask}
}

// MRZ sex codes map to ISO/IEC 23220-2's encoding, ISO/IEC 5218.
func TestISOEncodings(t *testing.T) {
	for mrz, want := range map[string]uint{"M": 1, "F": 2, "X": 0, "<": 0, "": 0} {
		if got := isoSex(mrz); got != want {
			t.Errorf("isoSex(%q) = %d, want %d", mrz, got, want)
		}
	}
}
