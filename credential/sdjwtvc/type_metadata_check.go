package sdjwtvc

import (
	"errors"
	"fmt"
	"math"
	"reflect"
)

// CheckTypeMetadata checks claims, as Issue would receive them, against
// m's claim metadata (SD-JWT VC draft-13 §9; draft-19 §5.6): a claim
// whose metadata is mandatory is present, one whose sd is "always" is
// selectively disclosable (SD, SDElement), and one whose sd is "never"
// isn't. A consumer that processes m refuses a credential that breaks
// these (draft-19 §5.7). m's vct, if set, must be claims'.
//
// Only m's own claims are checked: for a type that extends another
// (§6.4), pass a document whose Claims include what it inherits.
// Registered claims set through Claims' fields (iss, exp, status, cnf
// ...) are plaintext.
func CheckTypeMetadata(claims Claims, m TypeMetadata) error {
	if m.VCT != "" && m.VCT != claims.VCT {
		return fmt.Errorf("sdjwtvc: type metadata is for vct %q, not %q", m.VCT, claims.VCT)
	}
	tree := claimTree(claims)
	for i, c := range m.Claims {
		found, err := selectClaims(tree, c.Path)
		if err != nil {
			return fmt.Errorf("sdjwtvc: type metadata: claims[%d] %v: %w", i, c.Path, err)
		}
		if c.Mandatory && len(found) == 0 {
			return fmt.Errorf("sdjwtvc: type metadata: claims[%d] %v is mandatory, but the credential doesn't include it", i, c.Path)
		}
		for _, disclosable := range found {
			switch {
			case c.SD == SDAlways && !disclosable:
				return fmt.Errorf("sdjwtvc: type metadata: claims[%d] %v must be selectively disclosable (sd always)", i, c.Path)
			case c.SD == SDNever && disclosable:
				return fmt.Errorf("sdjwtvc: type metadata: claims[%d] %v must not be selectively disclosable (sd never)", i, c.Path)
			}
		}
	}
	return nil
}

// claimTree is claims' payload before sealing: Additional, with its SD
// and SDElement markers, and the registered claims Claims sets in
// plaintext.
func claimTree(claims Claims) map[string]any {
	tree := make(map[string]any, len(claims.Additional)+8)
	for k, v := range claims.Additional {
		tree[k] = v
	}
	plain := map[string]any{"vct": claims.VCT}
	if claims.Iss != "" {
		plain["iss"] = claims.Iss
	}
	if claims.Nbf != nil {
		plain["nbf"] = *claims.Nbf
	}
	if claims.Exp != nil {
		plain["exp"] = *claims.Exp
	}
	if claims.VCTIntegrity != "" {
		plain["vct#integrity"] = claims.VCTIntegrity
	}
	if claims.Status != nil {
		plain["status"] = claims.Status
	}
	if claims.CNF != nil {
		plain["cnf"] = claims.CNF
	}
	if len(claims.AkaVCTs) > 0 {
		plain["aka_vcts"] = claims.AkaVCTs
	}
	for k, v := range plain {
		tree[k] = v
	}
	return tree
}

// selectClaims follows path through tree (§9.1: a name selects an
// object property, an integer an array element, null every element) and
// reports, for each value it selects, whether that value is itself
// selectively disclosable.
func selectClaims(tree map[string]any, path []any) ([]bool, error) {
	type node struct {
		v           any
		disclosable bool
	}
	nodes := []node{{v: tree}}
	for _, step := range path {
		var next []node
		for _, n := range nodes {
			children, err := stepInto(n.v, step)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				v, disclosable := unwrapSD(child)
				next = append(next, node{v: v, disclosable: disclosable})
			}
		}
		nodes = next
	}
	found := make([]bool, len(nodes))
	for i, n := range nodes {
		found[i] = n.disclosable
	}
	return found, nil
}

// stepInto is what step selects in v: none when v hasn't it.
func stepInto(v, step any) ([]any, error) {
	rv := reflect.ValueOf(v)
	switch {
	case step == nil:
		return everyElement(rv), nil
	case isString(step):
		return member(rv, step.(string)), nil
	}
	idx, ok := pathIndex(step)
	if !ok {
		return nil, errors.New("a path element is neither a string, null nor a non-negative integer")
	}
	return element(rv, idx), nil
}

func isArray(rv reflect.Value) bool {
	return rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array
}

// everyElement is every element of rv, none when it isn't an array.
func everyElement(rv reflect.Value) []any {
	if !isArray(rv) {
		return nil
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out
}

// member is rv's property name, none when rv isn't an object or hasn't
// it.
func member(rv reflect.Value, name string) []any {
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil
	}
	child := rv.MapIndex(reflect.ValueOf(name).Convert(rv.Type().Key()))
	if !child.IsValid() {
		return nil
	}
	return []any{child.Interface()}
}

// element is rv's element idx, none when rv isn't an array that long.
func element(rv reflect.Value, idx int) []any {
	if !isArray(rv) || idx >= rv.Len() {
		return nil
	}
	return []any{rv.Index(idx).Interface()}
}

func isString(v any) bool {
	_, ok := v.(string)
	return ok
}

// pathIndex is a path element's array index: a non-negative integer,
// from Go or from JSON.
func pathIndex(step any) (int, bool) {
	switch n := step.(type) {
	case int:
		return n, n >= 0
	case int64:
		return int(n), n >= 0 && n <= math.MaxInt32
	case float64:
		return int(n), n >= 0 && n == math.Trunc(n) && n <= math.MaxInt32
	}
	return 0, false
}

// unwrapSD is v without an SD or SDElement marker, and whether it had
// one.
func unwrapSD(v any) (any, bool) {
	switch m := v.(type) {
	case sdValue:
		return m.v, true
	case sdElement:
		return m.v, true
	}
	return v, false
}
