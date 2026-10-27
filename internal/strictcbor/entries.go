package strictcbor

import (
	"errors"
	"io"
)

// Entries calls fn with the encoded key and value of each entry of the
// map data encodes, in order, without copying or decoding them: a
// large map is read without building it. data should be one a DecMode
// has walked, so its keys are distinct and its nesting within bounds;
// Entries refuses data that isn't a map.
func Entries(data []byte, fn func(key, value []byte) error) error {
	major, ai, arg, off, err := readHead(data, 0)
	if err != nil {
		return err
	}
	if major != majorMap {
		return errors.New("cbor: not a map")
	}
	for i := uint64(0); ai == aiIndefinite || i < arg; i++ {
		if ai == aiIndefinite {
			if off >= len(data) {
				return io.ErrUnexpectedEOF
			}
			if data[off] == breakCode {
				break
			}
		}
		keyEnd, err := skip(data, off)
		if err != nil {
			return err
		}
		end, err := skip(data, keyEnd)
		if err != nil {
			return err
		}
		if err := fn(data[off:keyEnd], data[keyEnd:end]); err != nil {
			return err
		}
		off = end
	}
	return nil
}

// Bytes returns the content of the byte string item encodes, reporting
// false for any other item. It copies the content only for an
// indefinite-length string, joining its chunks.
func Bytes(item []byte) ([]byte, bool) {
	major, ai, arg, off, err := readHead(item, 0)
	if err != nil || major != majorBytes {
		return nil, false
	}
	if ai != aiIndefinite {
		l, ok := span(item, off, arg)
		if !ok {
			return nil, false
		}
		return item[off : off+l : off+l], true
	}
	s := []byte{}
	for off < len(item) && item[off] != breakCode {
		cm, cai, n, chunk, err := readHead(item, off)
		if err != nil || cm != majorBytes || cai == aiIndefinite {
			return nil, false
		}
		l, ok := span(item, chunk, n)
		if !ok {
			return nil, false
		}
		s = append(s, item[chunk:chunk+l]...)
		off = chunk + l
	}
	return s[:len(s):len(s)], off < len(item)
}

// IsMap reports whether item encodes a map.
func IsMap(item []byte) bool {
	major, _, _, _, err := readHead(item, 0)
	return err == nil && major == majorMap
}
