package strictjson

import "testing"

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
