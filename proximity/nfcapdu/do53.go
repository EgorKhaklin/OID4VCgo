package nfcapdu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// MaxMessage is the largest session message NFC data retrieval carries
// in one DO53 object.
const MaxMessage = 2 << 20

// maxEncoded is the largest DO53 object: tag, a four-byte length field,
// and MaxMessage.
const maxEncoded = MaxMessage + 5

// WrapDO53 encodes message as an ISO/IEC 7816-4 DO53 (discretionary
// data) object, with the shortest BER length.
func WrapDO53(message []byte) ([]byte, error) {
	n := len(message)
	if n > MaxMessage {
		return nil, fmt.Errorf("nfcapdu: NFC message of %d bytes exceeds %d", n, MaxMessage)
	}
	out := make([]byte, 0, n+5)
	out = append(out, 0x53)
	switch {
	case n < 128:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = binary.BigEndian.AppendUint16(append(out, 0x82), uint16(n&0xffff))
	default:
		out = binary.BigEndian.AppendUint16(append(out, 0x83, byte(n>>16&0xff)), uint16(n&0xffff))
	}
	return append(out, message...), nil
}

// UnwrapDO53 decodes one DO53 object filling all of b. It refuses a
// non-canonical length, as WrapDO53 never sends one.
func UnwrapDO53(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != 0x53 {
		return nil, errors.New("nfcapdu: missing DO53")
	}
	first := int(b[1])
	count := 0
	if first >= 128 {
		count = first & 0x7f
	}
	if count > 3 || first == 0x80 || len(b) < 2+count {
		return nil, errors.New("nfcapdu: invalid DO53 length")
	}
	length := first
	if count > 0 {
		length = 0
		for _, c := range b[2 : 2+count] {
			length = length<<8 | int(c)
		}
	}
	if length > MaxMessage || length != len(b)-2-count {
		return nil, errors.New("nfcapdu: DO53 length mismatch")
	}
	if count > 0 && (length < 128 || b[2] == 0) {
		return nil, errors.New("nfcapdu: non-canonical DO53 length")
	}
	return bytes.Clone(b[2+count:]), nil
}
