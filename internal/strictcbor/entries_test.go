package strictcbor

import (
	"bytes"
	"errors"
	"testing"
)

func TestEntries(t *testing.T) {
	collect := func(data []byte) ([][2][]byte, error) {
		var got [][2][]byte
		err := Entries(data, func(k, v []byte) error {
			got = append(got, [2][]byte{k, v})
			return nil
		})
		return got, err
	}
	// {1: [2, {}], h'03': 0x5f 41 04 ff}, definite and indefinite.
	for _, data := range [][]byte{
		{0xa2, 0x01, 0x82, 0x02, 0xa0, 0x41, 0x03, 0x5f, 0x41, 0x04, 0xff},
		{0xbf, 0x01, 0x82, 0x02, 0xa0, 0x41, 0x03, 0x5f, 0x41, 0x04, 0xff, 0xff},
	} {
		got, err := collect(data)
		if err != nil || len(got) != 2 ||
			!bytes.Equal(got[0][0], []byte{0x01}) || !bytes.Equal(got[0][1], []byte{0x82, 0x02, 0xa0}) ||
			!bytes.Equal(got[1][0], []byte{0x41, 0x03}) || !bytes.Equal(got[1][1], []byte{0x5f, 0x41, 0x04, 0xff}) {
			t.Errorf("Entries(%x) = %x, %v", data, got, err)
		}
	}
	for name, data := range map[string][]byte{
		"not a map":            {0x80},
		"empty":                nil,
		"truncated":            {0xa1, 0x01},
		"unterminated":         {0xbf, 0x01, 0x02},
		"truncated value":      {0xa1, 0x01, 0x42, 0x00},
		"truncated tag":        {0xa1, 0x01, 0xc5},
		"huge length in value": {0xa1, 0x01, 0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, err := collect(data); err == nil {
			t.Errorf("%s: Entries(%x) = nil error", name, data)
		}
	}
	stop := errors.New("stop")
	if err := Entries([]byte{0xa1, 0x01, 0x02}, func(_, _ []byte) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("Entries = %v, want fn's error", err)
	}
}

func TestBytes(t *testing.T) {
	for _, tc := range []struct {
		item []byte
		want []byte
		ok   bool
	}{
		{[]byte{0x42, 0x01, 0x02}, []byte{0x01, 0x02}, true},
		{[]byte{0x40}, []byte{}, true},
		{[]byte{0x5f, 0x41, 0x01, 0x41, 0x02, 0xff}, []byte{0x01, 0x02}, true},
		{[]byte{0x5f, 0xff}, []byte{}, true},
		{[]byte{0x61, 'a'}, nil, false},
		{[]byte{0x5f, 0x61, 'a', 0xff}, nil, false},
		{[]byte{0x5f, 0x41, 0x01}, nil, false},
		{[]byte{0x5f, 0x5f, 0xff, 0xff}, nil, false},
		{[]byte{0x42, 0x01}, nil, false},
		{nil, nil, false},
	} {
		got, ok := Bytes(tc.item)
		if ok != tc.ok || ok && !bytes.Equal(got, tc.want) {
			t.Errorf("Bytes(%x) = %x, %v; want %x, %v", tc.item, got, ok, tc.want, tc.ok)
		}
		if ok && cap(got) != len(got) {
			t.Errorf("Bytes(%x) has room to grow into the input", tc.item)
		}
	}
	if !IsMap([]byte{0xa0}) || !IsMap([]byte{0xbf, 0xff}) || IsMap([]byte{0x80}) || IsMap(nil) {
		t.Error("IsMap")
	}
}
