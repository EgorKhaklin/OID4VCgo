package credential

import (
	"errors"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// Options controls validity and age claims for both encoders.
type Options struct {
	// Now is the issuance time.
	Now time.Time

	// MaxValidity is how long the credential is valid, counted from
	// the start of Now's UTC day (see ValidFrom); zero means one year.
	MaxValidity time.Duration

	// AgeThresholds are the ages to issue age claims for; nil means
	// DefaultAgeThresholds.
	AgeThresholds []int

	// IssuingCountry is the issuer's own country, ISO 3166-1 alpha-2:
	// its document signer certificate's countryName, and so the Photo
	// ID's issuing_country (ISO/IEC 23220-2 names the issuer's country
	// there, which verifiers hold to the document signer). Empty leaves
	// issuing_country out. The passport's own issuing country isn't it:
	// this issuer isn't the passport's.
	IssuingCountry string
}

func (o Options) thresholds() []int {
	if o.AgeThresholds == nil {
		return DefaultAgeThresholds
	}
	return o.AgeThresholds
}

// ErrNoValidity is returned when the credential would already be
// invalid at issuance.
var ErrNoValidity = errors.New("credential: passport evidence yields no validity period")

// ValidFrom is when a credential issued at now becomes valid: the start
// of now's UTC day. Every credential issued that day — every copy of a
// batch, and every holder's — then carries the same timestamps, so they
// neither link copies to one another nor let anyone who sees one find
// its issuance (sdjwtvc.RoundedExp's reasoning, RFC 9901 §10.1).
func ValidFrom(now time.Time) time.Time { return now.UTC().Truncate(24 * time.Hour) }

// ValidUntil is when a credential issued from e under o stops being
// valid: ValidFrom(o.Now) plus MaxValidity, the same for every holder.
//
// It never depends on the holder's birthday. Ending validity on the
// day an age_over_NN = false claim would become wrong put that
// birthday in exp (always disclosed) and the MSO's validUntil, so a
// verifier asking only age_over_16 learnt the exact date of birth of
// anyone about to turn 13, 16, 18, 21 or 65. Age claims that would
// change within the validity period are left out instead (see
// ageClaims).
//
// The passport's own expiry doesn't limit it. Expiry ends the document's
// use for travel, not the authenticity of its data; the credential
// carries expiry_date, and a verifier that cares checks that.
func ValidUntil(e passport.Evidence, o Options) (time.Time, error) {
	maxValidity := o.MaxValidity
	if maxValidity == 0 {
		maxValidity = defaultValidityYears * 365 * 24 * time.Hour
	}
	until := ValidFrom(o.Now).Add(maxValidity)
	if !until.After(o.Now) {
		return time.Time{}, ErrNoValidity
	}
	return until, nil
}

// ageClaims returns threshold → age_over value, derived from the
// youngest plausible birth date so an ambiguous MRZ year can only
// understate age. Empty when the passport has no usable birth date.
//
// A threshold the holder crosses before until is left out: its false
// would become wrong within the credential's validity, and ending
// validity on that birthday instead would disclose it (see ValidUntil).
// The trade-off is that a holder close to a threshold can't answer
// that age_over_NN at all until the next credential, and a verifier
// asking for it and getting nothing may take that to mean the holder
// reaches that age within the validity period: a year-long window for
// the date of birth, not the day. A verifier asking for anything else
// learns nothing of it: both encoders put a decoy digest in place of
// each left-out claim (ageDecoys).
func ageClaims(e passport.Evidence, o Options, until time.Time) map[int]bool {
	youngest := e.Identity.BirthDate.Youngest
	if youngest.IsZero() {
		return nil
	}
	age := passport.AgeOn(youngest, o.Now)
	ageAtExpiry := passport.AgeOn(youngest, until)
	out := make(map[int]bool, len(o.thresholds()))
	for _, t := range o.thresholds() {
		if age < t && ageAtExpiry >= t {
			continue
		}
		out[t] = age >= t
	}
	return out
}

// ageDecoys is how many decoy digests stand in for the age claims
// ageClaims left out of ages, so every credential carries as many
// digests for its age claims as o has thresholds. Both formats sign
// every claim's digest into what every verifier sees — the mdoc's MSO
// valueDigests, the SD-JWT VC's age_equal_or_over _sd array — so one
// fewer would say the holder crosses a threshold within the validity
// period, and with a disclosed age_over_NN narrow a minor's age to
// about a year. Padding to the full count hides that exactly. Random
// decoys on top of the real count instead wouldn't: the lowest and
// highest totals could only come from a credential with, and one
// without, a left-out claim. 0 when there are no age claims at all,
// which follows from the birth date, not from the validity period.
func ageDecoys(o Options, ages map[int]bool) int {
	if ages == nil {
		return 0
	}
	return len(o.thresholds()) - len(ages)
}
