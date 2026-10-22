// Package strictjson decodes JSON as encoding/json does, except that it
// refuses what parsers disagree on. encoding/json keeps the last of two
// members with one name, where other parsers keep the first, and also
// takes a member whose name matches a struct field only
// case-insensitively: {"nonce": "a", "Nonce": "b"} sets the field to
// "b", while a parser that matches names exactly, as JSON (RFC 8259
// §8.3) and JOSE (RFC 7515 §5.2) do, reads "a". For a signed or
// encrypted object, the two would then disagree on what was signed.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Unmarshal decodes data into v, refusing:
//   - an object, at any depth, with two members of one name (RFC 8259
//     §4: names "SHOULD be unique"; I-JSON, RFC 7493 §2.3, MUST);
//   - a member whose name matches one of a struct's fields only
//     case-insensitively, in v and in every struct reached through its
//     fields, slices, arrays and maps. A type with its own UnmarshalJSON
//     isn't looked into.
//
// That includes json.RawMessage: duplicates inside one are refused
// with the rest of the document, but its member names can only be
// checked against the type it is later decoded into, so decode it
// with Unmarshal too, never with encoding/json. A custom UnmarshalJSON
// on protocol data should likewise decode with Unmarshal.
func Unmarshal(data []byte, v any) error {
	// json.Valid bounds the nesting depth before checkDuplicates
	// recurses, and its error is encoding/json's own.
	if !json.Valid(data) {
		return json.Unmarshal(data, v)
	}
	if err := checkDuplicates(data); err != nil {
		return err
	}
	if t := reflect.TypeOf(v); t != nil && t.Kind() == reflect.Pointer {
		if err := checkCase(data, t.Elem()); err != nil {
			return err
		}
	}
	return json.Unmarshal(data, v)
}

// checkDuplicates refuses an object with two members of one name, at
// any depth.
func checkDuplicates(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkValue(dec)
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyTok.(string)
			if seen[key] {
				return fmt.Errorf("json: member %q appears twice in one object", key)
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// checkCase refuses, in data decoded as t, a member that matches a
// struct field's name only case-insensitively, following the members
// that name fields exactly into their types.
func checkCase(data []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	trimmed := bytes.TrimSpace(data)
	switch t.Kind() {
	case reflect.Struct:
		if !bytes.HasPrefix(trimmed, []byte("{")) {
			return nil // encoding/json reports the type mismatch
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &members); err != nil {
			return err
		}
		fields := fieldTypes(t)
		for member, raw := range members {
			if ft, ok := fields[member]; ok {
				if err := checkCase(raw, ft); err != nil {
					return err
				}
				continue
			}
			for name := range fields {
				if strings.EqualFold(member, name) {
					return fmt.Errorf("json: member %q isn't %q: names are case-sensitive", member, name)
				}
			}
		}
	case reflect.Slice, reflect.Array:
		if !bytes.HasPrefix(trimmed, []byte("[")) {
			return nil
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(trimmed, &elems); err != nil {
			return err
		}
		for _, e := range elems {
			if err := checkCase(e, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		if !bytes.HasPrefix(trimmed, []byte("{")) {
			return nil
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &members); err != nil {
			return err
		}
		for _, raw := range members {
			if err := checkCase(raw, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

var cache sync.Map // reflect.Type → map[string]reflect.Type

// fieldTypes maps the member names encoding/json maps to t's fields,
// including those of embedded structs, to the fields' types.
func fieldTypes(t reflect.Type) map[string]reflect.Type {
	if names, ok := cache.Load(t); ok {
		return names.(map[string]reflect.Type)
	}
	names := map[string]reflect.Type{}
	addFields(t, names)
	cache.Store(t, names)
	return names
}

func addFields(t reflect.Type, names map[string]reflect.Type) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				addFields(ft, names)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names[name] = f.Type
	}
}
