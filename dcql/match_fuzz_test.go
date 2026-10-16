package dcql_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// FuzzMatch feeds an arbitrary query and arbitrary claims, as a
// Verifier receives them from a holder, to the matching a presentation
// is checked with: SD-JWT VC claims of any shape (nesting, arrays, null
// and index paths, aka_vcts), and mdoc namespaces. A query that doesn't
// parse or validate is skipped: FuzzQuery covers that.
func FuzzMatch(f *testing.F) {
	sdQuery := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},
		"claims":[{"id":"a","path":["address","street"]},{"id":"b","path":["nationalities",null]},{"id":"c","path":["degrees",0,"name"]},{"path":["age"],"values":[18,true,"x"]}],
		"claim_sets":[["a","b"],["c"]]}]}`
	mdocQuery := `{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
		"claims":[{"path":["org.iso.18013.5.1","given_name"]},{"path":["org.iso.18013.5.1","age_over_18"],"values":[true]}]}]}`
	f.Add([]byte(sdQuery), []byte(`{"vct":"urn:example:pid","address":{"street":"Main"},"nationalities":["DE","FR"],"degrees":[{"name":"BSc"}],"age":18}`))
	f.Add([]byte(sdQuery), []byte(`{"vct":"urn:example:pid:derived","aka_vcts":["urn:example:pid"],"address":"not an object","nationalities":{"0":"DE"}}`))
	f.Add([]byte(sdQuery), []byte(`{"vct":1,"aka_vcts":"urn:example:pid","degrees":[null,[],{"name":null}]}`))
	f.Add([]byte(mdocQuery), []byte(`{"org.iso.18013.5.1":{"given_name":"Alice","age_over_18":true}}`))
	f.Add([]byte(mdocQuery), []byte(`{"org.iso.18013.5.1":{"age_over_18":"yes"},"other":{}}`))
	f.Fuzz(func(t *testing.T, queryJSON, claimsJSON []byte) {
		var q dcql.Query
		if err := json.Unmarshal(queryJSON, &q); err != nil || q.Validate() != nil {
			t.Skip()
		}
		var claims map[string]any
		if err := json.Unmarshal(claimsJSON, &claims); err != nil {
			t.Skip()
		}
		nameSpaces := map[string]map[string]any{}
		for ns, v := range claims {
			if elements, ok := v.(map[string]any); ok {
				nameSpaces[ns] = elements
			}
		}
		for _, cq := range q.Credentials {
			switch cq.Format {
			case "dc+sd-jwt":
				satisfied := cq.SatisfiedBySDJWTVCClaims(claims)
				paths, err := cq.SelectedSDJWTVCClaimPaths(claims)
				if (satisfied == nil) != (err == nil) {
					t.Fatalf("SatisfiedBySDJWTVCClaims = %v but SelectedSDJWTVCClaimPaths = %v", satisfied, err)
				}
				_ = paths
			case "mso_mdoc":
				docType := "org.iso.18013.5.1.mDL"
				satisfied := cq.SatisfiedByMdocClaims(docType, nameSpaces)
				_, err := cq.SelectedMdocClaimPaths(docType, nameSpaces)
				if (satisfied == nil) != (err == nil) {
					t.Fatalf("SatisfiedByMdocClaims = %v but SelectedMdocClaimPaths = %v", satisfied, err)
				}
			}
		}
		answered := map[string]bool{}
		for _, cq := range q.Credentials {
			answered[cq.ID] = len(claimsJSON)%2 == 0
		}
		_ = q.CheckAnswered(answered)
	})
}
