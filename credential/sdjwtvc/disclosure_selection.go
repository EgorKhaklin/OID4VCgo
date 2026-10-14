package sdjwtvc

import "fmt"

// SelectDisclosures returns the subset of all needed to disclose
// exactly the claims named by paths — RFC 9901 §7.2's own "the Holder
// MAY choose to not disclose ... some or all of the Disclosures".
// Each path is a sequence of top-level-then-nested object property
// names (e.g. []string{"address", "street_address"}) walked against
// payload — the Issuer JWT's own not-yet-resolved claims (still
// carrying "_sd"/"_sd_alg"), exactly what jose.DecodeUnverified's own
// payload return value is before ResolveDisclosures runs.
//
// Walking a path descends only through object properties — a
// mandatory (already-plaintext) one is followed directly; a
// selectively-disclosable one is resolved by finding its own
// Disclosure among the current object's "_sd" array, which is then
// included in the result. Once a path is fully walked, every
// Disclosure the target value itself transitively references
// (recursively, through further nested "_sd"/"..." entries — RFC 9901
// §4.2.6's own "recursive Disclosures", including array elements) is
// included too, so the disclosed value comes through intact rather
// than missing its own internal selectively-disclosed pieces. A path
// component absent from payload (a claim the credential doesn't
// actually carry) is silently skipped — asking to disclose a claim
// that isn't there discloses nothing for it, the same "ignore, don't
// error" stance ResolveDisclosures itself takes for an unmatched
// digest (§7.1 step 3.c.i).
//
// SelectDisclosures walks object members only; SelectDisclosuresAt
// also walks into arrays, by index or every element.
func SelectDisclosures(payload map[string]any, alg HashAlg, all []Disclosure, paths [][]string) ([]Disclosure, error) {
	general := make([][]any, len(paths))
	for i, path := range paths {
		general[i] = make([]any, len(path))
		for j, key := range path {
			general[i][j] = key
		}
	}
	return SelectDisclosuresAt(payload, alg, all, general)
}

// SelectDisclosuresAt is SelectDisclosures for claims path pointers
// that also walk into arrays (OpenID4VP §7.1): each path component is a
// string (an object member), a non-negative int (one array element) or
// nil (every element of an array). An array element is either a plain
// value or, when selectively disclosable, a {"...": digest} placeholder
// whose Disclosure is then included (RFC 9901 §4.2.4.2). An index
// counts the elements the holder's credential has, so placeholders with
// no matching Disclosure (decoys) aren't counted. As for an absent
// member, an index past the array's end selects nothing.
func SelectDisclosuresAt(payload map[string]any, alg HashAlg, all []Disclosure, paths [][]any) ([]Disclosure, error) {
	byDigest := make(map[string]Disclosure, len(all))
	for _, d := range all {
		digest, err := d.Digest(alg)
		if err != nil {
			return nil, err
		}
		byDigest[digest] = d
	}

	selected := make(map[string]Disclosure)
	for _, path := range paths {
		if err := selectPath(payload, byDigest, path, selected); err != nil {
			return nil, err
		}
	}

	out := make([]Disclosure, 0, len(selected))
	for _, d := range selected {
		out = append(out, d)
	}
	return out, nil
}

// selectPath walks node — a raw, not-yet-resolved SD-JWT subtree —
// following path, marking every Disclosure traversed along the way
// into selected (keyed by digest, so revisiting the same one via a
// different path is a no-op).
func selectPath(node any, byDigest map[string]Disclosure, path []any, selected map[string]Disclosure) error {
	if len(path) == 0 {
		return includeAllDisclosures(node, byDigest, selected)
	}
	switch c := path[0].(type) {
	case string:
		return selectMember(node, byDigest, c, path[1:], selected)
	case int:
		if c < 0 {
			return fmt.Errorf("sdjwtvc: select disclosures: negative array index %d", c)
		}
		return selectElements(node, byDigest, c, path[1:], selected)
	case nil:
		return selectElements(node, byDigest, -1, path[1:], selected)
	default:
		return fmt.Errorf("sdjwtvc: select disclosures: path component %v is neither a string, an int nor nil", c)
	}
}

// selectMember is selectPath for an object member key: a plaintext one
// is followed directly, a selectively disclosable one through its
// Disclosure among the object's "_sd" digests.
func selectMember(node any, byDigest map[string]Disclosure, key string, rest []any, selected map[string]Disclosure) error {
	obj, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("sdjwtvc: select disclosures: path element %q: not an object", key)
	}
	if child, present := obj[key]; present {
		return selectPath(child, byDigest, rest, selected)
	}
	for _, digest := range sdDigests(obj) {
		d, found := byDigest[digest]
		if !found || d.IsArrayElement() || d.Name != key {
			continue
		}
		selected[digest] = d
		return selectPath(d.Value, byDigest, rest, selected)
	}
	return nil
}

// selectElements is selectPath for an array: element index, or every
// element when index is -1. Under a wildcard, an element the rest of
// the path can't walk (another type than it expects) is skipped, as
// OpenID4VP §7.1 drops it from the selection.
func selectElements(node any, byDigest map[string]Disclosure, index int, rest []any, selected map[string]Disclosure) error {
	arr, ok := node.([]any)
	if !ok {
		return fmt.Errorf("sdjwtvc: select disclosures: path element %v: not an array", indexComponent(index))
	}
	position := 0
	for _, el := range arr {
		value, digest := el, ""
		if ref, isRef := disclosureRefDigest(el); isRef {
			d, found := byDigest[ref]
			if !found {
				continue // a decoy, which the holder's credential doesn't have
			}
			value, digest = d.Value, ref
		}
		if index == -1 || position == index {
			if index == -1 && !walkable(value, rest) {
				position++
				continue
			}
			if digest != "" {
				selected[digest] = byDigest[digest]
			}
			if err := selectPath(value, byDigest, rest, selected); err != nil {
				return err
			}
			if index != -1 {
				return nil
			}
		}
		position++
	}
	return nil
}

// walkable reports whether value has the type rest's first component
// walks: an object for a member, an array for an index or wildcard.
func walkable(value any, rest []any) bool {
	if len(rest) == 0 {
		return true
	}
	if _, member := rest[0].(string); member {
		_, ok := value.(map[string]any)
		return ok
	}
	_, ok := value.([]any)
	return ok
}

// indexComponent is index as a path component, for an error.
func indexComponent(index int) any {
	if index == -1 {
		return nil
	}
	return index
}

// sdDigests returns obj's own "_sd" array entries that are actually
// strings — the digest list every level of a not-yet-resolved SD-JWT
// payload carries, per RFC 9901 §4.1.1. A non-string entry is silently
// skipped rather than treated as an error, the same "malformed input
// degrades gracefully" stance byDigest lookups elsewhere in this file
// already take for a digest with no matching Disclosure.
func sdDigests(obj map[string]any) []string {
	raw, _ := obj["_sd"].([]any)
	digests := make([]string, 0, len(raw))
	for _, item := range raw {
		if digest, ok := item.(string); ok {
			digests = append(digests, digest)
		}
	}
	return digests
}

// includeAllDisclosures marks every Disclosure node transitively
// references — recursively, through nested "_sd" object entries and
// "..." array entries — as selected. Called once a path has been
// fully walked, so the disclosed target value comes through with its
// own internal selective disclosures intact rather than left as
// unresolved digest stubs.
func includeAllDisclosures(node any, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	switch t := node.(type) {
	case map[string]any:
		return includeAllDisclosuresInObject(t, byDigest, selected)
	case []any:
		return includeAllDisclosuresInArray(t, byDigest, selected)
	}
	return nil
}

// includeAllDisclosuresInObject and includeAllDisclosuresInArray are
// includeAllDisclosures's own two case bodies (map[string]any/[]any),
// split into top-level helpers purely to keep it under the linter's
// own cognitive complexity ceiling.
func includeAllDisclosuresInObject(obj map[string]any, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	for k, v := range obj {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		if err := includeAllDisclosures(v, byDigest, selected); err != nil {
			return err
		}
	}
	for _, digest := range sdDigests(obj) {
		if err := includeDisclosure(digest, byDigest, selected); err != nil {
			return err
		}
	}
	return nil
}

func includeAllDisclosuresInArray(arr []any, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	for _, el := range arr {
		if digest, isRef := disclosureRefDigest(el); isRef {
			if err := includeDisclosure(digest, byDigest, selected); err != nil {
				return err
			}
			continue
		}
		if err := includeAllDisclosures(el, byDigest, selected); err != nil {
			return err
		}
	}
	return nil
}

// disclosureRefDigest reports whether el is an RFC 9901 §4.2.6
// recursive-disclosure array-element reference (a single-key object
// {"...": "<digest>"}), returning its own digest if so.
func disclosureRefDigest(el any) (digest string, isRef bool) {
	obj, ok := el.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", false
	}
	digestRaw, has := obj["..."]
	if !has {
		return "", false
	}
	digest, ok = digestRaw.(string)
	return digest, ok
}

// includeDisclosure marks digest's own Disclosure as selected (a
// digest with no matching Disclosure is silently ignored, same as
// elsewhere) and recurses into its own value.
func includeDisclosure(digest string, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	if _, already := selected[digest]; already {
		return nil
	}
	d, found := byDigest[digest]
	if !found {
		return nil
	}
	selected[digest] = d
	return includeAllDisclosures(d.Value, byDigest, selected)
}
