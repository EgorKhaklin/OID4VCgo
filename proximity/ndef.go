package proximity

import (
	"encoding/binary"
	"fmt"
)

// MaxNDEFBytes is the largest NDEF message a two-byte Type 4 NLEN can
// describe. Bound messages before parsing or allocating their records.
const MaxNDEFBytes = 65535

const maxNDEFRecords = 128

// ndefRecord is an NFC Forum NDEF record. Slices refer to the parsed
// message, so callers retaining data beyond parsing must copy it.
type ndefRecord struct {
	tnf              byte
	typ, id, payload []byte
}

func parseNDEF(b []byte) ([]ndefRecord, error) {
	if len(b) == 0 || len(b) > MaxNDEFBytes {
		return nil, fmt.Errorf("proximity: NDEF message length %d is out of range", len(b))
	}
	var records []ndefRecord
	for pos := 0; pos < len(b); {
		if len(records) == maxNDEFRecords || len(b)-pos < 3 {
			return nil, fmt.Errorf("proximity: too many or truncated NDEF records")
		}
		flags, typeLen := b[pos], int(b[pos+1])
		pos += 2
		if (flags&0x80 != 0) != (len(records) == 0) || flags&0x20 != 0 {
			return nil, fmt.Errorf("proximity: invalid NDEF message boundary or chunked record")
		}
		var payloadLen uint32
		if flags&0x10 != 0 {
			payloadLen = uint32(b[pos])
			pos++
		} else {
			if len(b)-pos < 4 {
				return nil, fmt.Errorf("proximity: truncated NDEF payload length")
			}
			payloadLen = binary.BigEndian.Uint32(b[pos : pos+4])
			pos += 4
		}
		idLen := 0
		if payloadLen > MaxNDEFBytes {
			return nil, fmt.Errorf("proximity: NDEF payload too large")
		}
		if flags&8 != 0 {
			if pos == len(b) {
				return nil, fmt.Errorf("proximity: missing NDEF ID length")
			}
			idLen = int(b[pos])
			pos++
		}
		// Each term is bounded (255, 255, 65535), including on 32-bit.
		payloadSize := int(payloadLen)
		if typeLen+idLen+payloadSize > len(b)-pos {
			return nil, fmt.Errorf("proximity: truncated NDEF record")
		}
		r := ndefRecord{tnf: flags & 7}
		r.typ = b[pos : pos+typeLen]
		pos += typeLen
		r.id = b[pos : pos+idLen]
		pos += idLen
		r.payload = b[pos : pos+int(payloadLen)]
		pos += int(payloadLen)
		if err := validateNDEFRecord(r); err != nil {
			return nil, err
		}
		records = append(records, r)
		if flags&0x40 != 0 {
			if pos != len(b) {
				return nil, fmt.Errorf("proximity: bytes after NDEF message end")
			}
			return records, nil
		}
	}
	return nil, fmt.Errorf("proximity: NDEF message has no end record")
}

func validateNDEFRecord(r ndefRecord) error {
	switch r.tnf {
	case 0:
		if len(r.typ)+len(r.id)+len(r.payload) != 0 {
			return fmt.Errorf("proximity: nonempty NDEF Empty record")
		}
	case 1, 2, 3, 4:
		if len(r.typ) == 0 {
			return fmt.Errorf("proximity: NDEF record has no type")
		}
	case 5:
		if len(r.typ) != 0 {
			return fmt.Errorf("proximity: NDEF Unknown record has a type")
		}
	default:
		return fmt.Errorf("proximity: unsupported NDEF TNF %d", r.tnf)
	}
	return nil
}

func encodeNDEF(records []ndefRecord) ([]byte, error) {
	if len(records) == 0 || len(records) > maxNDEFRecords {
		return nil, fmt.Errorf("proximity: invalid NDEF record count")
	}
	var out []byte
	for i, r := range records {
		if err := validateNDEFRecord(r); err != nil {
			return nil, err
		}
		if len(r.typ) > 255 || len(r.id) > 255 || len(r.payload) > MaxNDEFBytes {
			return nil, fmt.Errorf("proximity: NDEF record too large")
		}
		flags := r.tnf
		if i == 0 {
			flags |= 0x80
		}
		if i == len(records)-1 {
			flags |= 0x40
		}
		if len(r.payload) < 256 {
			flags |= 0x10
		}
		if len(r.id) != 0 {
			flags |= 8
		}
		out = append(out, flags, byte(len(r.typ)&0xff))
		if flags&0x10 != 0 {
			out = append(out, byte(len(r.payload)&0xff))
		} else {
			out = binary.BigEndian.AppendUint32(out, uint32(len(r.payload)&0xffff))
		}
		if flags&8 != 0 {
			out = append(out, byte(len(r.id)&0xff))
		}
		out = append(out, r.typ...)
		out = append(out, r.id...)
		out = append(out, r.payload...)
		if len(out) > MaxNDEFBytes {
			return nil, fmt.Errorf("proximity: NDEF message too large")
		}
	}
	return out, nil
}
