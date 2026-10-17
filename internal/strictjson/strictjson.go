// Package strictjson decodes JSON into a struct as encoding/json does,
// except that a member must name a field exactly. encoding/json also
// takes a member whose name matches a field only case-insensitively,
// so {"nonce": "a", "Nonce": "b"} sets the field to "b", while a parser
// that matches names exactly, as JSON (RFC 8259 §8.3) and JOSE (RFC
// 7515 §5.2) do, reads "a". For a signed or encrypted object, the two
// would then disagree on what was signed.
package strictjson

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Unmarshal decodes data into v, refusing a top-level member whose
// name matches one of v's fields only case-insensitively. v that isn't
// a pointer to a struct is decoded as json.Unmarshal does.
func Unmarshal(data []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Pointer || t.Elem().Kind() != reflect.Struct {
		return json.Unmarshal(data, v)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	names := fieldNames(t.Elem())
	for member := range members {
		if names[member] {
			continue
		}
		for name := range names {
			if strings.EqualFold(member, name) {
				return fmt.Errorf("json: member %q isn't %q: names are case-sensitive", member, name)
			}
		}
	}
	return json.Unmarshal(data, v)
}

var cache sync.Map // reflect.Type → map[string]bool

// fieldNames are the member names encoding/json maps to t's fields,
// including those of embedded structs.
func fieldNames(t reflect.Type) map[string]bool {
	if names, ok := cache.Load(t); ok {
		return names.(map[string]bool)
	}
	names := map[string]bool{}
	addFields(t, names)
	cache.Store(t, names)
	return names
}

func addFields(t reflect.Type, names map[string]bool) {
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
		names[name] = true
	}
}
