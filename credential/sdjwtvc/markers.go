package sdjwtvc

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// SD marks value as a selectively disclosable object property
// (RFC 9901 §4.2.1) when used as a value in a map[string]any passed to
// Issue via Claims.Additional. It has no effect used anywhere else in
// the claim tree.
func SD(value any) any { return sdValue{value} }

// SDElement marks value as a selectively disclosable array element
// (RFC 9901 §4.2.2) when used as an element of a []any passed to Issue.
// It has no effect used anywhere else in the claim tree.
func SDElement(value any) any { return sdElement{value} }

// WithDecoys marks object, a map[string]any (or another map Issue seals
// the same way), to carry n decoy digests (RFC 9901 §4.2.5) in its _sd
// array, creating one if it has no selectively disclosable claim: use
// it in the claim tree passed to Issue wherever the object itself would
// go, inside SD() too. It pads an object whose number of selectively
// disclosable claims would otherwise say something — which of a fixed
// set of claims were left out, say — to a count that doesn't. The top
// level's own decoys are IssueOptions.Decoys. Issue rejects an n below
// 0 or above MaxDecoys, and an object that isn't one.
func WithDecoys(object any, n int) any { return withDecoys{object, n} }

type sdValue struct{ v any }
type sdElement struct{ v any }
type withDecoys struct {
	v any
	n int
}

// sealer seals a claims tree under alg. nestedDecoys, if set, is called
// once for each _sd array below the top level sealing produces, for
// how many decoys to add to it (IssueOptions.NestedDecoys).
type sealer struct {
	alg          HashAlg
	nestedDecoys func() (int, error)
}

// sealMap seals m as a top-level claims object, with no decoys at any
// level.
func sealMap(m map[string]any, alg HashAlg) (map[string]any, []Disclosure, error) {
	return sealer{alg: alg}.sealObject(m, 0, false)
}

// seal walks a claims tree, replacing every SD/SDElement marker with
// its digest — embedded per RFC 9901 §4.2.4 — and collecting the
// corresponding Disclosures, recursively. A disclosed value that itself
// contains further markers therefore produces §4.2.6 "recursive
// Disclosures" with no special-casing: sealing an outer SD() value
// first seals its contents, so the outer Disclosure's own value already
// has any inner digests embedded in it.
func (s sealer) seal(v any) (any, []Disclosure, error) {
	switch t := v.(type) {
	case map[string]any:
		return s.sealObject(t, 0, true)
	case []any:
		return s.sealArray(t)
	case withDecoys:
		return s.sealWithDecoys(t)
	case sdValue:
		return nil, nil, fmt.Errorf("sdjwtvc: SD() used outside an object property value")
	case sdElement:
		return nil, nil, fmt.Errorf("sdjwtvc: SDElement() used outside an array element")
	default:
		if generic, ok := asGeneric(v); ok {
			return s.seal(generic)
		}
		if hasSDMarker(v) {
			return nil, nil, fmt.Errorf("sdjwtvc: an SD, SDElement or WithDecoys marker inside a %T, which Issue can't seal: use map[string]any and []any around it", v)
		}
		if !isJSONScalar(v) {
			// A struct, json.Marshaler (json.RawMessage, say) or other
			// value with an encoding of its own is sealed as the JSON
			// it encodes to, so a reserved name inside it — user
			// input copied into a claim planting an _sd digest the
			// Holder could later disclose a claim of its own choosing
			// for — is refused like one in a map[string]any.
			generic, err := toGenericJSON(v)
			if err != nil {
				return nil, nil, err
			}
			return s.seal(generic)
		}
		return v, nil, nil
	}
}

// isJSONScalar reports whether v encodes as a JSON null, boolean,
// number or string with no encoding of its own, so holds no object
// key at all.
func isJSONScalar(v any) bool {
	if v == nil {
		return true
	}
	if _, ok := v.(json.Marshaler); ok {
		return false
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// toGenericJSON is v as the map[string]any, []any and scalars it
// encodes to, numbers as json.Number so they encode again exactly as
// v did.
func toGenericJSON(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("sdjwtvc: encode a %T claim value: %w", v, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("sdjwtvc: decode a %T claim value: %w", v, err)
	}
	return out, nil
}

// isReservedName reports whether name is one of the claim names RFC
// 9901 reserves for the SD-JWT's own structure (§4.2.4.1, §4.2.4.2,
// §4.1.1), which only Issue's sealing may place.
func isReservedName(name string) bool {
	return name == "_sd" || name == "..." || name == "_sd_alg"
}

// reservedNameIn is the first reserved name (isReservedName) used as
// an object key anywhere in v, a map[string]any/[]any tree, if any.
func reservedNameIn(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if isReservedName(k) {
				return k, true
			}
			if name, ok := reservedNameIn(child); ok {
				return name, true
			}
		}
	case []any:
		for _, child := range t {
			if name, ok := reservedNameIn(child); ok {
				return name, true
			}
		}
	}
	return "", false
}

// sealWithDecoys seals a WithDecoys object, with its decoys.
func (s sealer) sealWithDecoys(w withDecoys) (any, []Disclosure, error) {
	if w.n < 0 || w.n > MaxDecoys {
		return nil, nil, fmt.Errorf("sdjwtvc: WithDecoys count %d is outside 0..%d", w.n, MaxDecoys)
	}
	m, ok := w.v.(map[string]any)
	if !ok {
		generic, isGeneric := asGeneric(w.v)
		if m, ok = generic.(map[string]any); !isGeneric || !ok {
			return nil, nil, fmt.Errorf("sdjwtvc: WithDecoys needs an object, not a %T", w.v)
		}
	}
	return s.sealObject(m, w.n, true)
}

// asGeneric is v as a map[string]any or []any, when it's another map
// with string keys or slice that JSON encodes the same way, so a marker
// inside a typed container ([]map[string]any, say) is sealed rather
// than encoded as an empty object. Anything with an encoding of its
// own keeps it: a []byte (base64), a json.Marshaler, a nil map or
// slice (null), and a map whose keys marshal as text.
func asGeneric(v any) (any, bool) {
	if v == nil {
		return nil, false
	}
	if _, ok := v.(json.Marshaler); ok {
		return nil, false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		key := rv.Type().Key()
		if rv.IsNil() || key.Kind() != reflect.String || key.Implements(textMarshalerType) {
			return nil, false
		}
		out := make(map[string]any, rv.Len())
		for it := rv.MapRange(); it.Next(); {
			out[it.Key().String()] = it.Value().Interface()
		}
		return out, true
	case reflect.Slice:
		if rv.IsNil() || rv.Type().Elem().Kind() == reflect.Uint8 {
			return nil, false
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = rv.Index(i).Interface()
		}
		return out, true
	}
	return nil, false
}

var (
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
	sdValueType       = reflect.TypeFor[sdValue]()
	sdElementType     = reflect.TypeFor[sdElement]()
	withDecoysType    = reflect.TypeFor[withDecoys]()
)

// sealObject seals the object m, adding decoys decoy digests to its _sd
// array and, when nested (m isn't the top level), as many more as
// s.nestedDecoys says if m has an _sd array at all.
func (s sealer) sealObject(m map[string]any, decoys int, nested bool) (map[string]any, []Disclosure, error) {
	out := make(map[string]any, len(m))
	var digests []string
	var disclosures []Disclosure

	for k, v := range m {
		if isReservedName(k) {
			return nil, nil, fmt.Errorf("sdjwtvc: claim name %q is reserved", k)
		}
		if sv, ok := v.(sdValue); ok {
			sealedInner, innerDs, err := s.seal(sv.v)
			if err != nil {
				return nil, nil, err
			}
			d, err := NewObjectDisclosure(k, sealedInner)
			if err != nil {
				return nil, nil, err
			}
			digest, err := d.Digest(s.alg)
			if err != nil {
				return nil, nil, err
			}
			digests = append(digests, digest)
			disclosures = append(disclosures, d)
			disclosures = append(disclosures, innerDs...)
			continue
		}
		sealed, ds, err := s.seal(v)
		if err != nil {
			return nil, nil, err
		}
		out[k] = sealed
		disclosures = append(disclosures, ds...)
	}

	if nested && s.nestedDecoys != nil && (len(digests) > 0 || decoys > 0) {
		n, err := s.nestedDecoys()
		if err != nil {
			return nil, nil, err
		}
		if n < 0 || n > MaxDecoys {
			return nil, nil, fmt.Errorf("sdjwtvc: nested decoy count %d is outside 0..%d", n, MaxDecoys)
		}
		decoys += n
	}
	decoyDigests, err := newDecoyDigests(s.alg, decoys)
	if err != nil {
		return nil, nil, err
	}
	digests = append(digests, decoyDigests...)

	if len(digests) > 0 {
		// RFC 9901 §4.2.4.1: the Issuer MUST hide the original claim
		// order. Sorting is a simple, deterministic way to do that —
		// the spec only requires the method not depend on the
		// original order, not that it be random. It mixes any decoys
		// in among the real digests too.
		sort.Strings(digests)
		sd := make([]any, len(digests))
		for i, dg := range digests {
			sd[i] = dg
		}
		out["_sd"] = sd
	}
	return out, disclosures, nil
}

func (s sealer) sealArray(arr []any) ([]any, []Disclosure, error) {
	out := make([]any, 0, len(arr))
	var disclosures []Disclosure

	for _, el := range arr {
		if se, ok := el.(sdElement); ok {
			sealedInner, innerDs, err := s.seal(se.v)
			if err != nil {
				return nil, nil, err
			}
			d, err := NewArrayElementDisclosure(sealedInner)
			if err != nil {
				return nil, nil, err
			}
			digest, err := d.Digest(s.alg)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, map[string]any{"...": digest})
			disclosures = append(disclosures, d)
			disclosures = append(disclosures, innerDs...)
			continue
		}
		sealed, ds, err := s.seal(el)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, sealed)
		disclosures = append(disclosures, ds...)
	}
	return out, disclosures, nil
}

// newDecoyDigests is n decoy digests (RFC 9901 §4.2.5) under alg: each
// the digest of a fresh 128-bit random salt from crypto/rand, so a
// decoy has no real Disclosure behind it and looks like any other
// digest.
func newDecoyDigests(alg HashAlg, n int) ([]string, error) {
	if n == 0 {
		return nil, nil
	}
	out := make([]string, 0, n)
	for range n {
		salt, err := newSalt()
		if err != nil {
			return nil, err
		}
		digest, err := hashString(alg, salt)
		if err != nil {
			return nil, err
		}
		out = append(out, digest)
	}
	return out, nil
}

// addDecoys adds n decoy digests (RFC 9901 §4.2.5) to payload's
// top-level _sd array, creating it if necessary. Nested objects get
// theirs while they're sealed (sealer.sealObject).
func addDecoys(payload map[string]any, alg HashAlg, n int) error {
	if n < 0 || n > MaxDecoys {
		return fmt.Errorf("sdjwtvc: decoy count %d is outside 0..%d", n, MaxDecoys)
	}
	existing, _ := payload["_sd"].([]any)
	// Capacity for the existing digests only; append grows it for the
	// (at most MaxDecoys) decoys, rather than pre-sizing with
	// len(existing)+n.
	digests := make([]string, 0, len(existing))
	for _, d := range existing {
		if s, ok := d.(string); ok {
			digests = append(digests, s)
		}
	}
	decoys, err := newDecoyDigests(alg, n)
	if err != nil {
		return err
	}
	digests = append(digests, decoys...)
	sort.Strings(digests)
	sd := make([]any, len(digests))
	for i, d := range digests {
		sd[i] = d
	}
	payload["_sd"] = sd
	return nil
}

// hasSDMarker reports whether v holds an SD, SDElement or WithDecoys
// marker at any depth, through maps, slices, arrays, pointers, interfaces and struct
// fields.
func hasSDMarker(v any) bool {
	return hasSDMarkerValue(reflect.ValueOf(v), 0)
}

// maxMarkerDepth bounds hasSDMarker's walk, which a pointer cycle would
// otherwise never end.
const maxMarkerDepth = 64

func hasSDMarkerValue(rv reflect.Value, depth int) bool {
	if !rv.IsValid() || depth > maxMarkerDepth {
		return false
	}
	if t := rv.Type(); t == sdValueType || t == sdElementType || t == withDecoysType {
		return true
	}
	switch rv.Kind() {
	case reflect.Interface, reflect.Pointer:
		return !rv.IsNil() && hasSDMarkerValue(rv.Elem(), depth+1)
	case reflect.Map:
		return mapHasSDMarker(rv, depth)
	case reflect.Slice, reflect.Array:
		return elemsHaveSDMarker(rv, depth)
	case reflect.Struct:
		return fieldsHaveSDMarker(rv, depth)
	}
	return false
}

// mapHasSDMarker is hasSDMarkerValue for the values of the map rv.
func mapHasSDMarker(rv reflect.Value, depth int) bool {
	for it := rv.MapRange(); it.Next(); {
		if hasSDMarkerValue(it.Value(), depth+1) {
			return true
		}
	}
	return false
}

// elemsHaveSDMarker is hasSDMarkerValue for the elements of the slice
// or array rv.
func elemsHaveSDMarker(rv reflect.Value, depth int) bool {
	for i := range rv.Len() {
		if hasSDMarkerValue(rv.Index(i), depth+1) {
			return true
		}
	}
	return false
}

// fieldsHaveSDMarker is hasSDMarkerValue for the fields of the struct
// rv.
func fieldsHaveSDMarker(rv reflect.Value, depth int) bool {
	for i := range rv.NumField() {
		if hasSDMarkerValue(rv.Field(i), depth+1) {
			return true
		}
	}
	return false
}
