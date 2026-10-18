package strictjson

import (
	"encoding/json"
	"testing"
)

type inner struct {
	Kid string `json:"kid"`
}

type claims struct {
	inner
	Nonce   string `json:"nonce"`
	Aud     string `json:"aud,omitempty"`
	Ignored string `json:"-"`
	Plain   string
}

func TestUnmarshal(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"nonce":"a","aud":"b","kid":"k","Plain":"p","other":1}`: true,
		`{"nonce":"a","Nonce":"b"}`:                               false,
		`{"NONCE":"a"}`:                                           false,
		`{"Kid":"k"}`:                                             false,
		`{"plain":"p"}`:                                           false,
		`[1]`:                                                     false,
	} {
		var c claims
		if err := Unmarshal([]byte(in), &c); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
	var c claims
	if err := Unmarshal([]byte(`{"nonce":"a","kid":"k"}`), &c); err != nil || c.Nonce != "a" || c.Kid != "k" {
		t.Errorf("decoded %+v, %v", c, err)
	}
	var m map[string]any
	if err := Unmarshal([]byte(`{"A":1,"a":2}`), &m); err != nil || len(m) != 2 {
		t.Errorf("a map: %v, %v", m, err)
	}
}

type outer struct {
	Claims  claims            `json:"claims"`
	List    []claims          `json:"list"`
	ByName  map[string]claims `json:"by_name"`
	Pointer *claims           `json:"pointer"`
	Raw     json.RawMessage   `json:"raw"`
}

// Duplicate members are refused at every depth, and a case-only match
// is refused in every struct reached through fields, slices, maps and
// pointers. A json.Unmarshaler (RawMessage) isn't looked into for case.
func TestUnmarshalNested(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"claims":{"nonce":"a"},"list":[{"nonce":"b"}],"by_name":{"x":{"nonce":"c"}},"pointer":{"nonce":"d"}}`: true,
		`{"nonce":"a","nonce":"b"}`:                     false,
		`{"claims":{"nonce":"a","nonce":"b"}}`:          false,
		`{"raw":{"x":1,"x":2}}`:                         false,
		`{"other":[{"k":1,"k":2}]}`:                     false,
		`{"claims":{"NONCE":"a"}}`:                      false,
		`{"list":[{"nonce":"a"},{"Nonce":"b"}]}`:        false,
		`{"by_name":{"x":{"Aud":"a"}}}`:                 false,
		`{"pointer":{"KID":"k"}}`:                       false,
		`{"raw":{"Nonce":"a","nonce":"b"}}`:             true,
		`{"other":{"Nonce":"a"},"Other":{"nonce":"b"}}`: true,
	} {
		var o outer
		if err := Unmarshal([]byte(in), &o); (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", in, err, ok)
		}
	}
	var m map[string]any
	if err := Unmarshal([]byte(`{"a":{"b":1,"b":2}}`), &m); err == nil {
		t.Error("a map with a nested duplicate was accepted")
	}
}
