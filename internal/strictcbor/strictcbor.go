// Package strictcbor makes a CBOR decoder's duplicate map key check
// cover the whole data item. fxamacker/cbor's DupMapKeyEnforcedAPF
// refuses a duplicate key in what it decodes, but copies a
// cbor.RawMessage member's bytes unexamined: {1: {2: 3, 2: 4}} decodes
// into map[int]cbor.RawMessage without error. A fragment hashed, signed
// or passed on as it is would then carry a map other decoders read
// differently (RFC 8949 §5.6: a map with duplicate keys isn't valid).
//
// Bytes inside a byte string, such as #6.24(bstr .cbor X), are checked
// when they are decoded, through the same DecMode.
package strictcbor

import "github.com/fxamacker/cbor/v2"

// DecMode is a cbor.DecMode whose Unmarshal, UnmarshalFirst and
// Wellformed first decode the item into an empty interface, with the
// same options, so its duplicate map key setting applies at every
// depth.
type DecMode struct {
	cbor.DecMode
}

// Wrap returns mode, checking whole items. mode should refuse duplicate
// map keys (cbor.DupMapKeyEnforcedAPF).
func Wrap(mode cbor.DecMode) DecMode {
	return DecMode{mode}
}

// Unmarshal decodes data, one CBOR data item, into v.
func (m DecMode) Unmarshal(data []byte, v any) error {
	var item any
	if err := m.DecMode.Unmarshal(data, &item); err != nil {
		return err
	}
	return m.DecMode.Unmarshal(data, v)
}

// UnmarshalFirst decodes data's first CBOR data item into v and returns
// the bytes after it.
func (m DecMode) UnmarshalFirst(data []byte, v any) ([]byte, error) {
	var item any
	if _, err := m.DecMode.UnmarshalFirst(data, &item); err != nil {
		return nil, err
	}
	return m.DecMode.UnmarshalFirst(data, v)
}

// Wellformed reports whether data is one well-formed CBOR data item
// that the mode decodes, duplicate map keys included.
func (m DecMode) Wellformed(data []byte) error {
	var item any
	return m.DecMode.Unmarshal(data, &item)
}
