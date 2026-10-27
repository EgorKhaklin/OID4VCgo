package walletflow

import (
	"encoding/base64"
	"math"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// copyMarks are what a copy shows every Verifier it's presented to,
// whatever the holder discloses, that should differ between copies:
// its disclosure digests (an SD-JWT VC's _sd and array element digests,
// an mdoc's valueDigests), and those of its validity timestamps the
// issuer didn't round to the day (an SD-JWT VC's iat, nbf and exp, an
// mdoc's validityInfo signed, validFrom and validUntil), by name. Two
// copies sharing a digest are the same to a Verifier, and so are two
// sharing a timestamp to the second: rounded to the day, every
// credential the issuer issued that day shares it, so it says little.
type copyMarks struct {
	digests []string
	times   map[string]int64
}

// marksOf is credential's copyMarks, in format: none for a credential
// it can't read, which verifyCopy has already checked.
func marksOf(format, credential string) copyMarks {
	switch format {
	case sdjwtvc.CredentialFormat:
		return sdjwtvcMarks(credential)
	case mdoc.CredentialFormat:
		return mdocMarks(credential)
	}
	return copyMarks{}
}

// marksShared reports whether two of marks, each a copy's, share a
// digest or a timestamp: one pass over them all, keyed by what's
// shared.
func marksShared(marks []copyMarks) bool {
	type timestamp struct {
		name string
		at   int64
	}
	digestOf := map[string]int{}
	timeOf := map[timestamp]int{}
	for i, m := range marks {
		for _, d := range m.digests {
			if j, seen := digestOf[d]; seen && j != i {
				return true
			}
			digestOf[d] = i
		}
		for name, at := range m.times {
			if _, seen := timeOf[timestamp{name, at}]; seen {
				return true
			}
			timeOf[timestamp{name, at}] = i
		}
	}
	return false
}

// sdjwtvcTimes are an SD-JWT VC's validity timestamps (RFC 7519 §4.1).
var sdjwtvcTimes = []string{"iat", "nbf", "exp"}

// sdjwtvcMarks are an SD-JWT VC's copyMarks: the digests in its Issuer
// JWT payload and Disclosures, and its timestamps not on a UTC day
// boundary.
func sdjwtvcMarks(credential string) copyMarks {
	pres, err := sdjwtvc.Parse(credential)
	if err != nil {
		return copyMarks{}
	}
	_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return copyMarks{}
	}
	var payload map[string]any
	if strictjson.Unmarshal(raw, &payload) != nil {
		return copyMarks{}
	}
	m := copyMarks{times: map[string]int64{}}
	m.digests = appendDigests(nil, payload, 0)
	for _, d := range pres.Disclosures {
		m.digests = appendDigests(m.digests, d.Value, 0)
	}
	for _, name := range sdjwtvcTimes {
		v, ok := payload[name].(float64)
		if ok && !dayAligned(v) {
			m.times[name] = int64(math.Floor(v))
		}
	}
	return m
}

// appendDigests appends to out the digests in v, a raw SD-JWT value:
// each object's "_sd" entries and each {"...": digest} array element
// (RFC 9901 §4.2.4), walked no deeper than sdjwtvc.MaxResolveDepth.
func appendDigests(out []string, v any, depth int) []string {
	if depth > sdjwtvc.MaxResolveDepth {
		return out
	}
	switch t := v.(type) {
	case map[string]any:
		if digest, ok := t["..."].(string); ok && len(t) == 1 {
			return append(out, digest)
		}
		sd, _ := t["_sd"].([]any)
		for _, d := range sd {
			if digest, ok := d.(string); ok {
				out = append(out, digest)
			}
		}
		for k, child := range t {
			if k != "_sd" {
				out = appendDigests(out, child, depth+1)
			}
		}
	case []any:
		for _, child := range t {
			out = appendDigests(out, child, depth+1)
		}
	}
	return out
}

// dayAligned reports whether v, a NumericDate, is the start of a UTC
// day (sdjwtvc.RoundedExp's, with a lifetime of whole days).
func dayAligned(v float64) bool {
	return v == math.Trunc(v) && math.Mod(v, 86400) == 0
}

// mdocMarks are an mdoc's copyMarks: its MSO's valueDigests, and its
// validityInfo timestamps, expectedUpdate among them, not on a UTC day
// boundary (mdoc.RoundedValidity's, with a lifetime of whole days).
func mdocMarks(credential string) copyMarks {
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		return copyMarks{}
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return copyMarks{}
	}
	mso, err := mdoc.IssuerAuthMSO(issuerSigned)
	if err != nil {
		return copyMarks{}
	}
	m := copyMarks{times: map[string]int64{}}
	for _, ids := range mso.ValueDigests {
		for _, d := range ids {
			m.digests = append(m.digests, string(d))
		}
	}
	times := map[string]time.Time{
		"signed": mso.ValidityInfo.Signed, "validFrom": mso.ValidityInfo.ValidFrom, "validUntil": mso.ValidityInfo.ValidUntil,
	}
	if mso.ValidityInfo.ExpectedUpdate != nil {
		times["expectedUpdate"] = *mso.ValidityInfo.ExpectedUpdate
	}
	for name, at := range times {
		if !at.IsZero() && !at.Equal(at.UTC().Truncate(24*time.Hour)) {
			m.times[name] = at.Unix()
		}
	}
	return m
}
