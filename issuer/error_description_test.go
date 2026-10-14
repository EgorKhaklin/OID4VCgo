package issuer

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// error_description carries only printable ASCII without '"' or '\'
// (RFC 6749 5.2, OID4VCI 8.3.1.2).
func TestWriteJSONSanitisesDescription(t *testing.T) {
	rec := httptest.NewRecorder()
	newError(ErrorInvalidProof, 400, "alg \"none\" in C:\\path\nnaïve", nil).WriteJSON(rec)
	var body struct {
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if want := "alg 'none' in C:?path?na?ve"; body.Description != want {
		t.Errorf("error_description = %q, want %q", body.Description, want)
	}
}
