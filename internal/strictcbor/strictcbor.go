// Package strictcbor makes a CBOR decoder's duplicate map key check
// cover the whole data item, and bounds how many data items one
// message may hold. fxamacker/cbor's DupMapKeyEnforcedAPF refuses a
// duplicate key in what it decodes, but copies a cbor.RawMessage
// member's bytes unexamined: {1: {2: 3, 2: 4}} decodes into
// map[int]cbor.RawMessage without error. A fragment hashed, signed or
// passed on as it is would then carry a map other decoders read
// differently (RFC 8949 §5.6: a map with duplicate keys isn't valid).
//
// The mode's MaxArrayElements and MaxMapPairs bound each container, not
// the message: {"x": [[{} × 4096] × 250]} keeps within a 4096 cap at
// every level and still holds a million maps in 1 MB. DecMode walks the
// encoded bytes first, without building them, and refuses more than
// MaxItems data items in all; WithBudget extends the count over the
// parts of a message decoded one at a time.
//
// Bytes inside a byte string, such as #6.24(bstr .cbor X), are checked
// when they are decoded, through the same DecMode.
package strictcbor

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

// DefaultMaxItems is the most data items Wrap's DecMode accepts in one
// message: every array, map, tag, integer, string, string chunk and
// simple value, map keys included. Real ISO/IEC 18013-5 and COSE
// messages hold hundreds; a data element's or an MSO's own items are
// counted when its #6.24 byte string is decoded.
const DefaultMaxItems = 1 << 16

// DecMode is a cbor.DecMode whose Unmarshal, UnmarshalFirst and
// Wellformed first walk the encoded item, refusing duplicate map keys at
// every depth and more than its MaxItems data items, and then decode it
// with the wrapped mode.
type DecMode struct {
	cbor.DecMode
	maxItems int
	// budget, if set, is shared by all of this mode's calls.
	budget *budget
}

// A budget is a number of data items several walks share.
type budget struct {
	total, left int
}

// Wrap returns mode, checking whole items, with DefaultMaxItems. mode
// should refuse duplicate map keys (cbor.DupMapKeyEnforcedAPF). Wrap
// panics if mode decodes integers, byte strings, tags or maps to types
// that change which map keys are equal or which items decode, since the
// walk checks items as fxamacker/cbor's default options decode them. A
// mode with registered tags (cbor.TagSet) isn't supported.
func Wrap(mode cbor.DecMode) DecMode {
	o := mode.DecOptions()
	if o.DefaultByteStringType != nil || o.ByteStringToString != cbor.ByteStringToStringForbidden ||
		o.ByteStringExpectedFormat != cbor.ByteStringExpectedFormatNone ||
		o.UnrecognizedTagToAny != cbor.UnrecognizedTagNumAndContentToAny ||
		o.TimeTagToAny != cbor.TimeTagToTime || o.IntDec != cbor.IntDecConvertNone || o.DefaultMapType != nil {
		panic("strictcbor: mode decodes items other than as the walk checks them")
	}
	return DecMode{DecMode: mode, maxItems: DefaultMaxItems}
}

// WithMaxItems returns m refusing more than n data items in one
// message.
func (m DecMode) WithMaxItems(n int) DecMode {
	m.maxItems = n
	return m
}

// WithBudget returns m with one budget of n data items for all its
// calls, and those of modes derived from it, together. A message whose
// parts are decoded one at a time, such as the #6.24 byte strings of an
// mdoc's data elements, takes one: each part keeps within MaxItems, but
// the parts together would hold as many items as the message's length
// allows. The returned mode isn't safe for concurrent use.
func (m DecMode) WithBudget(n int) DecMode {
	m.budget = &budget{total: n, left: n}
	return m
}

// MaxItems is the most data items m accepts in one message.
func (m DecMode) MaxItems() int {
	if m.maxItems <= 0 {
		return DefaultMaxItems
	}
	return m.maxItems
}

// Unmarshal decodes data, one CBOR data item, into v.
func (m DecMode) Unmarshal(data []byte, v any) error {
	if err := m.walk(data, true); err != nil {
		return err
	}
	return m.DecMode.Unmarshal(data, v)
}

// UnmarshalFirst decodes data's first CBOR data item into v and returns
// the bytes after it.
func (m DecMode) UnmarshalFirst(data []byte, v any) ([]byte, error) {
	if err := m.walk(data, false); err != nil {
		return nil, err
	}
	return m.DecMode.UnmarshalFirst(data, v)
}

// Wellformed reports whether data is one well-formed CBOR data item
// that the mode decodes, duplicate map keys and the item count
// included. It builds nothing.
func (m DecMode) Wellformed(data []byte) error {
	if err := m.walk(data, true); err != nil {
		return err
	}
	return m.DecMode.Wellformed(data)
}

// Defaults fxamacker/cbor applies to a zero option.
const (
	defaultMaxNestedLevels = 32
	defaultMaxContainer    = 131072
)

// walk checks data's first item, and that nothing follows it if whole.
func (m DecMode) walk(data []byte, whole bool) error {
	o := m.DecOptions()
	w := walker{
		mode:      m.DecMode,
		data:      data,
		maxItems:  m.MaxItems(),
		maxNested: cmp.Or(o.MaxNestedLevels, defaultMaxNestedLevels),
		maxArray:  cmp.Or(o.MaxArrayElements, defaultMaxContainer),
		maxPairs:  cmp.Or(o.MaxMapPairs, defaultMaxContainer),
		checkUTF8: o.UTF8 == cbor.UTF8RejectInvalid,
		bstrKeys:  o.MapKeyByteString == cbor.MapKeyByteStringAllowed,
	}
	if m.budget != nil {
		w.maxItems = min(w.maxItems, m.budget.left)
		defer func() { m.budget.left -= w.items }()
	}
	if len(data) == 0 {
		return io.EOF
	}
	if err := w.item(0); err != nil {
		if errors.Is(err, errTooManyItems) && m.budget != nil && w.maxItems < m.MaxItems() {
			return fmt.Errorf("cbor: more than %d data items in the message", m.budget.total)
		}
		if errors.Is(err, errTooManyItems) {
			return fmt.Errorf("cbor: more than %d data items", w.maxItems)
		}
		return err
	}
	if whole && w.off != len(data) {
		return fmt.Errorf("cbor: %d bytes of extraneous data starting at index %d", len(data)-w.off, w.off)
	}
	return nil
}

// walker checks one encoded data item in place. It allocates only for
// the keys of a map whose keys aren't in deterministic order (see
// mapWalk) and for the rare key or tag it hands to the wrapped mode, so
// its cost follows the input's length, not what decoding it would
// build.
type walker struct {
	mode      cbor.DecMode
	data      []byte
	off       int
	items     int
	maxItems  int
	maxNested int
	maxArray  int
	maxPairs  int
	checkUTF8 bool
	bstrKeys  bool
	// keys holds the keys of the maps being walked, innermost last.
	keys []mapKey
}

var (
	errMalformed    = errors.New("cbor: malformed data item")
	errTooManyItems = errors.New("cbor: too many data items")
)

const (
	majorUint = iota
	majorNint
	majorBytes
	majorText
	majorArray
	majorMap
	majorTag
	majorSimple
)

const (
	aiIndefinite = 31
	breakCode    = 0xff
)

// readHead reads the data item head at data[off]: its major type,
// additional information and argument, and the offset after it.
func readHead(data []byte, off int) (major, ai byte, arg uint64, next int, err error) {
	if off >= len(data) {
		return 0, 0, 0, 0, io.ErrUnexpectedEOF
	}
	b := data[off]
	major, ai = b>>5, b&0x1f
	off++
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai <= 27:
		n := 1 << (ai - 24)
		if len(data)-off < n {
			return 0, 0, 0, 0, io.ErrUnexpectedEOF
		}
		for _, c := range data[off : off+n] {
			arg = arg<<8 | uint64(c)
		}
		off += n
		// RFC 8949 §3.3: a two-byte simple value below 32 isn't
		// well-formed.
		if major == majorSimple && ai == 24 && arg < 32 {
			return 0, 0, 0, 0, errMalformed
		}
	case ai == aiIndefinite:
		// Only strings, arrays and maps have an indefinite length; a
		// break outside one isn't well-formed.
		if major != majorBytes && major != majorText && major != majorArray && major != majorMap {
			return 0, 0, 0, 0, errMalformed
		}
	default:
		return 0, 0, 0, 0, errMalformed
	}
	return major, ai, arg, off, nil
}

// head reads and counts the head at w.off.
func (w *walker) head() (major, ai byte, arg uint64, err error) {
	major, ai, arg, w.off, err = readHead(w.data, w.off)
	if err != nil {
		return 0, 0, 0, err
	}
	w.items++
	if w.items > w.maxItems {
		return 0, 0, 0, errTooManyItems
	}
	return major, ai, arg, nil
}

// atBreak reports whether an indefinite-length item ends at w.off, and
// consumes the break if so.
func (w *walker) atBreak() (bool, error) {
	if w.off >= len(w.data) {
		return false, io.ErrUnexpectedEOF
	}
	if w.data[w.off] == breakCode {
		w.off++
		return true, nil
	}
	return false, nil
}

// item walks the data item at w.off, depth arrays, maps or nested tags
// deep. Depth counts as fxamacker/cbor's own check does, so the walk
// refuses no item the wrapped mode would accept for nesting.
func (w *walker) item(depth int) error {
	start := w.off
	major, ai, arg, err := w.head()
	if err != nil {
		return err
	}
	switch major {
	case majorBytes, majorText:
		if ai != aiIndefinite {
			return w.chunk(major, arg)
		}
		return w.chunks(major)
	case majorArray, majorMap:
		depth++
		if depth > w.maxNested {
			return fmt.Errorf("cbor: exceeded max nested level %d", w.maxNested)
		}
		if major == majorMap {
			return w.mapItems(depth, ai == aiIndefinite, arg)
		}
		return w.arrayItems(depth, ai == aiIndefinite, arg)
	case majorTag:
		return w.tag(depth, start, arg)
	}
	return nil
}

// span is n as an int, if n bytes, or items of at least a byte, could
// follow off in data. No input this module decodes nears 2 GiB.
func span(data []byte, off int, n uint64) (int, bool) {
	if n > math.MaxInt32 {
		return 0, false
	}
	l := int(n)
	return l, l <= len(data)-off
}

// chunk skips a definite-length string's n content bytes.
func (w *walker) chunk(major byte, n uint64) error {
	l, ok := span(w.data, w.off, n)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	s := w.data[w.off : w.off+l]
	w.off += l
	if major == majorText && w.checkUTF8 && !utf8.Valid(s) {
		return errors.New("cbor: invalid UTF-8 string")
	}
	return nil
}

// chunks skips an indefinite-length string's chunks, each a
// definite-length string of the same major type, up to its break.
func (w *walker) chunks(major byte) error {
	for {
		done, err := w.atBreak()
		if err != nil || done {
			return err
		}
		cm, cai, carg, err := w.head()
		if err != nil {
			return err
		}
		if cm != major || cai == aiIndefinite {
			return errMalformed
		}
		if err := w.chunk(major, carg); err != nil {
			return err
		}
	}
}

// Formats of the errors for a container with more items than allowed,
// worded as the wrapped mode words them.
const (
	tooManyElements = "cbor: exceeded max number of elements %d for CBOR array"
	tooManyPairs    = "cbor: exceeded max number of key-value pairs %d for CBOR map"
)

// length is a definite-length container's n items as an int, if they
// could follow w.off taking at least per bytes each, refused past
// limit.
func (w *walker) length(n uint64, per, limit int, tooMany string) (int, error) {
	l, ok := span(w.data, w.off, n)
	if !ok || per*l > len(w.data)-w.off {
		return 0, io.ErrUnexpectedEOF
	}
	if l > limit {
		return 0, fmt.Errorf(tooMany, limit)
	}
	return l, nil
}

// another reports whether a container has an item i: a definite-length
// one, of count; an indefinite-length one, before its break, refused
// past limit.
func (w *walker) another(indefinite bool, i, count, limit int, tooMany string) (bool, error) {
	if !indefinite {
		return i < count, nil
	}
	done, err := w.atBreak()
	if err != nil || done {
		return false, err
	}
	if i >= limit {
		return false, fmt.Errorf(tooMany, limit)
	}
	return true, nil
}

func (w *walker) arrayItems(depth int, indefinite bool, n uint64) error {
	count := 0
	if !indefinite {
		var err error
		if count, err = w.length(n, 1, w.maxArray, tooManyElements); err != nil {
			return err
		}
	}
	for i := 0; ; i++ {
		more, err := w.another(indefinite, i, count, w.maxArray, tooManyElements)
		if err != nil || !more {
			return err
		}
		if err := w.item(depth); err != nil {
			return err
		}
	}
}

func (w *walker) mapItems(depth int, indefinite bool, n uint64) error {
	count := 0
	if !indefinite {
		var err error
		if count, err = w.length(n, 2, w.maxPairs, tooManyPairs); err != nil {
			return err
		}
	}
	m := mapWalk{base: len(w.keys), first: w.off, ascending: true}
	defer func() { w.keys = w.keys[:m.base] }()
	for i := 0; ; i++ {
		more, err := w.another(indefinite, i, count, w.maxPairs, tooManyPairs)
		if err != nil {
			return err
		}
		if !more {
			break
		}
		if err := w.pair(depth, indefinite, i, count, &m); err != nil {
			return err
		}
	}
	return duplicateKey(w.keys[m.base:])
}

// A mapWalk is what the walk of one map keeps to find a duplicate key.
// While the map's keys come in strictly ascending order — compareKeys's,
// which a deterministically encoded map's keys follow (RFC 8949
// §4.2.1) — none can repeat one before it, so only the last is kept: a
// large canonical map costs no memory. At the first key out of order,
// the keys before it are read again from first and, with every key
// after them, kept in w.keys from base for duplicateKey.
type mapWalk struct {
	base, first int
	ascending   bool
	// last is the last key while ascending, if any.
	last    mapKey
	hasLast bool
	// other holds the keys only their decoded value identifies.
	other map[any]struct{}
}

// pair walks a map's entry i, of count if definite-length: its key,
// recorded to find a duplicate, then its value.
func (w *walker) pair(depth int, indefinite bool, i, count int, m *mapWalk) error {
	keyStart := w.off
	if err := w.item(depth); err != nil {
		return err
	}
	k, err := w.key(keyStart, w.off)
	if err != nil {
		return err
	}
	if err := w.record(k, i, keyStart, count, m); err != nil {
		return err
	}
	if indefinite {
		if done, err := w.atBreak(); err != nil {
			return err
		} else if done {
			return errors.New(`cbor: unexpected "break" code`)
		}
	}
	return w.item(depth)
}

// record notes key k, of entry i starting at keyStart, for
// duplicateKey; a key only its decoded value identifies is instead
// checked against, and added to, m.other.
func (w *walker) record(k mapKey, i, keyStart, count int, m *mapWalk) error {
	if k.kind == kindOther {
		if m.other == nil {
			m.other = make(map[any]struct{})
		}
		if _, dup := m.other[k.other]; dup {
			return &cbor.DupMapKeyError{Key: k.other, Index: i}
		}
		m.other[k.other] = struct{}{}
		return nil
	}
	k.index = i
	if m.ascending {
		if !m.hasLast || compareKeys(m.last, k) < 0 {
			m.last, m.hasLast = k, true
			return nil
		}
		m.ascending = false
		if err := w.keysBefore(m, keyStart, max(count, i+1)); err != nil {
			return err
		}
	}
	w.keys = append(w.keys, k)
	return nil
}

// keysBefore keeps the keys of the map's entries from m.first to
// keyStart, which the walk has checked, with room for n keys in all.
func (w *walker) keysBefore(m *mapWalk, keyStart, n int) error {
	w.keys = slices.Grow(w.keys, n)
	for i, off := 0, m.first; off < keyStart; i++ {
		end, err := skip(w.data, off)
		if err != nil {
			return err
		}
		k, err := w.key(off, end)
		if err != nil {
			return err
		}
		if k.kind != kindOther {
			k.index = i
			w.keys = append(w.keys, k)
		}
		if off, err = skip(w.data, end); err != nil {
			return err
		}
	}
	return nil
}

// skip returns the offset after the data item at data[off], which the
// walk has checked, so its nesting is within bounds.
func skip(data []byte, off int) (int, error) {
	major, ai, arg, off, err := readHead(data, off)
	if err != nil {
		return 0, err
	}
	switch major {
	case majorTag:
		return skip(data, off)
	case majorBytes, majorText, majorArray, majorMap:
	default:
		return off, nil
	}
	if ai == aiIndefinite {
		for {
			if off >= len(data) {
				return 0, io.ErrUnexpectedEOF
			}
			if data[off] == breakCode {
				return off + 1, nil
			}
			if off, err = skip(data, off); err != nil {
				return 0, err
			}
		}
	}
	n, ok := span(data, off, arg)
	if !ok {
		return 0, io.ErrUnexpectedEOF
	}
	switch major {
	case majorBytes, majorText:
		return off + n, nil
	case majorMap:
		n *= 2
	}
	for range n {
		if off, err = skip(data, off); err != nil {
			return 0, err
		}
	}
	return off, nil
}

// tag walks a chain of tags and their content. start is the first tag's
// head; its number, already read, is num. Like the wrapped mode, the
// walk counts each tag after the first as a nesting level and checks
// the content type of the tags it knows (RFC 8949 §3.4: tdate, epoch
// time and bignums).
func (w *walker) tag(depth, start int, num uint64) error {
	timeTag := -1
	for {
		if w.off >= len(w.data) {
			return io.ErrUnexpectedEOF
		}
		if err := validTagContent(num, w.data[w.off]); err != nil {
			return err
		}
		if num == 0 || num == 1 {
			timeTag = start
		}
		if w.data[w.off]>>5 != majorTag {
			break
		}
		start = w.off
		_, _, n, err := w.head()
		if err != nil {
			return err
		}
		num = n
		depth++
		if depth > w.maxNested {
			return fmt.Errorf("cbor: exceeded max nested level %d", w.maxNested)
		}
	}
	if err := w.item(depth); err != nil {
		return err
	}
	if timeTag >= 0 {
		// A time's content is a single string or number: decoding it
		// checks the date (RFC 3339) or range as the wrapped mode
		// does, building one time.Time.
		var t any
		if err := w.mode.Unmarshal(w.data[timeTag:w.off], &t); err != nil {
			return err
		}
	}
	return nil
}

// validTagContent checks the initial byte of a tag's content for the
// tag numbers whose content RFC 8949 §3.4 fixes, as fxamacker/cbor does
// when decoding.
func validTagContent(num uint64, content byte) error {
	major := content >> 5
	ok := true
	switch num {
	case 0:
		ok = major == majorText
	case 1:
		ok = major == majorUint || major == majorNint || content >= 0xf9 && content <= 0xfb
	case 2, 3:
		ok = major == majorBytes
	}
	if !ok {
		return fmt.Errorf("cbor: tag number %d has the wrong content type", num)
	}
	return nil
}

// A mapKey identifies a map key as the Go value fxamacker/cbor decodes
// it to under its default options, which DupMapKeyEnforcedAPF compares
// with ==. Comparing encoded bytes wouldn't do: 1 and its non-shortest
// form 0x18 0x01, a text string and its indefinite-length chunks, a
// half- and a double-precision 1.0, and null and undefined each decode
// to the same value. Integers, strings, simple values and floats, which
// cover what ISO/IEC 18013-5 and COSE use, are compared without
// decoding. A tagged key is decoded by the wrapped mode, to a cbor.Tag
// or a time.Time, which no untagged key equals.
type mapKey struct {
	kind uint8
	// n is an integer's argument, a simple value's number, or a float's
	// bits.
	n uint64
	// s is a string's content: the input's own bytes, or its chunks
	// joined.
	s []byte
	// other is a tagged key as the wrapped mode decodes it.
	other any
	// index is the key's place in its map.
	index int
}

const (
	kindUint uint8 = iota
	kindNint
	kindBytes
	kindText
	kindSimple
	kindFloat
	// kindNaN is never equal to another key, as NaN != NaN.
	kindNaN
	kindOther
)

// simpleNil is the number both null (22) and undefined (23) take: both
// decode to nil.
const simpleNil = 22

// key identifies the map key encoded in w.data[start:end], which item
// has already walked.
func (w *walker) key(start, end int) (mapKey, error) {
	// A key's self-described CBOR tags (RFC 8949 §3.4.6) are dropped
	// when it is decoded: 55799(1) is the key 1.
	off := start
	major, ai, arg, next, err := readHead(w.data, off)
	for err == nil && major == majorTag && arg == 55799 {
		off = next
		major, ai, arg, next, err = readHead(w.data, off)
	}
	if err != nil {
		return mapKey{}, err
	}
	switch major {
	case majorUint:
		return mapKey{kind: kindUint, n: arg}, nil
	case majorNint:
		if arg > math.MaxInt64 {
			// Decodes to a big.Int, which can't be a Go map key.
			return mapKey{}, errors.New("cbor: invalid map key type: big.Int")
		}
		return mapKey{kind: kindNint, n: arg}, nil
	case majorBytes, majorText:
		return w.stringKey(major, ai, arg, next)
	case majorArray, majorMap:
		return mapKey{}, errors.New("cbor: invalid map key type: array or map")
	case majorSimple:
		return simpleKey(ai, arg, w.data[off+1:next]), nil
	}
	// A tag: rare in a key, so it's decoded as the wrapped mode does,
	// as the one key of a map, to get the same Go value or error.
	enc := make([]byte, 0, end-start+2)
	enc = append(enc, 0xa1)
	enc = append(enc, w.data[start:end]...)
	enc = append(enc, 0xf6)
	var m any
	if err := w.mode.Unmarshal(enc, &m); err != nil {
		return mapKey{}, err
	}
	for k := range m.(map[any]any) {
		return mapKey{kind: kindOther, other: k}, nil
	}
	return mapKey{}, errMalformed
}

// stringKey identifies a byte or text string key whose head, of major
// type major, additional information ai and argument arg, ends at
// next: item has already walked it.
func (w *walker) stringKey(major, ai byte, arg uint64, next int) (mapKey, error) {
	kind := kindText
	if major == majorBytes {
		if !w.bstrKeys {
			return mapKey{}, errors.New("cbor: invalid map key type: []uint8")
		}
		kind = kindBytes
	}
	if ai != aiIndefinite {
		l, _ := span(w.data, next, arg)
		return mapKey{kind: kind, s: w.data[next : next+l]}, nil
	}
	var s []byte
	for off := next; w.data[off] != breakCode; {
		_, _, n, chunk, _ := readHead(w.data, off)
		l, _ := span(w.data, chunk, n)
		s = append(s, w.data[chunk:chunk+l]...)
		off = chunk + l
	}
	return mapKey{kind: kind, s: s}, nil
}

// simpleKey identifies a simple value or float key from its additional
// information, argument and argument bytes.
func simpleKey(ai byte, arg uint64, b []byte) mapKey {
	var f float64
	switch ai {
	case 23:
		return mapKey{kind: kindSimple, n: simpleNil}
	case 25:
		f = halfToFloat64(binary.BigEndian.Uint16(b))
	case 26:
		f = float64(math.Float32frombits(binary.BigEndian.Uint32(b)))
	case 27:
		f = math.Float64frombits(arg)
	default:
		return mapKey{kind: kindSimple, n: arg}
	}
	if math.IsNaN(f) {
		return mapKey{kind: kindNaN}
	}
	if f == 0 {
		f = 0 // -0 == 0
	}
	return mapKey{kind: kindFloat, n: math.Float64bits(f)}
}

// halfToFloat64 converts an IEEE 754 half-precision float (RFC 8949
// Appendix D).
func halfToFloat64(h uint16) float64 {
	exp := int(h >> 10 & 0x1f)
	mant := float64(h & 0x3ff)
	var f float64
	switch exp {
	case 0:
		f = math.Ldexp(mant, -24)
	case 0x1f:
		if mant == 0 {
			f = math.Inf(1)
		} else {
			f = math.NaN()
		}
	default:
		f = math.Ldexp(mant+1024, exp-25)
	}
	if h&0x8000 != 0 {
		return -f
	}
	return f
}

// duplicateKey reports a duplicate among keys, sorting them in place.
func duplicateKey(keys []mapKey) error {
	if len(keys) < 2 {
		return nil
	}
	slices.SortFunc(keys, compareKeys)
	for i := 1; i < len(keys); i++ {
		if keys[i].kind != kindNaN && compareKeys(keys[i-1], keys[i]) == 0 {
			return &cbor.DupMapKeyError{Key: keys[i].value(), Index: max(keys[i-1].index, keys[i].index)}
		}
	}
	return nil
}

// compareKeys orders keys as RFC 8949 §4.2.1 orders the deterministic
// encodings of integers and definite-length strings: by major type,
// then argument, then a string's bytes. Keys that decode to the same
// value compare equal.
func compareKeys(a, b mapKey) int {
	return cmp.Or(
		cmp.Compare(a.kind, b.kind),
		cmp.Compare(a.n, b.n),
		cmp.Compare(len(a.s), len(b.s)),
		bytes.Compare(a.s, b.s),
	)
}

// value is k as a Go value, for an error message.
func (k mapKey) value() any {
	switch k.kind {
	case kindUint:
		return k.n
	case kindNint:
		return fmt.Sprintf("-1-%d", k.n)
	case kindBytes:
		return cbor.ByteString(k.s)
	case kindText:
		return string(k.s)
	case kindFloat:
		return math.Float64frombits(k.n)
	}
	return fmt.Sprintf("simple(%d)", k.n)
}
