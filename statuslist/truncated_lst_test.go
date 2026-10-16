package statuslist

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A list whose compressed stream is cut short, or whose checksum is
// wrong, is refused, even at an index whose byte inflated before the
// damage: it isn't a valid list (draft-14 §8.3 step 5). An intact list
// still answers, and an index past its end is out of bounds.
func TestStatus_RefusesTruncatedOrCorruptList(t *testing.T) {
	statuses := make([]uint8, 4096)
	for i := range statuses {
		statuses[i] = uint8(i % 2)
	}
	sl, err := New(Bits1, statuses, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sl.Lst)
	if err != nil {
		t.Fatal(err)
	}
	with := func(b []byte) StatusList {
		out := sl
		out.Lst = base64.RawURLEncoding.EncodeToString(b)
		return out
	}

	if got, err := sl.Status(1); err != nil || got != 1 {
		t.Fatalf("intact list: Status(1) = %d, %v; want 1", got, err)
	}
	if _, err := sl.Status(len(statuses) + 8); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Errorf("intact list, past its end: %v, want out of bounds", err)
	}

	corrupt := append([]byte{}, raw...)
	corrupt[len(corrupt)-1] ^= 0xff // the Adler-32 checksum's last byte
	for name, list := range map[string]StatusList{
		"checksum missing":   with(raw[:len(raw)-4]),
		"checksum cut short": with(raw[:len(raw)-2]),
		"deflate cut short":  with(raw[:len(raw)/2]),
		"checksum wrong":     with(corrupt),
	} {
		if _, err := list.Status(1); err == nil {
			t.Errorf("%s: Status(1) answered from an incomplete list", name)
		}
	}
}
