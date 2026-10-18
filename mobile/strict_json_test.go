package mobile

import "testing"

// A configuration is refused for a key no field has, one that names a
// field only case-insensitively, or anything after the object.
func TestDecodeConfig(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"development":true,"client_id":"w"}`: true,
		`{"require_trusted_mdoc_readr":true}`:  false,
		`{"DEVELOPMENT":true}`:                 false,
		`{"development":true} {"x":1}`:         false,
		`{"development":true} trailing`:        false,
		`[]`:                                   false,
	} {
		var cfg config
		if err := decodeConfig(in, &cfg); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
	var reader proximityReaderConfig
	if err := decodeConfig(`{"require_mdl_signer_ekus":true}`, &reader); err == nil {
		t.Error("a misspelled reader option was accepted")
	}
}
