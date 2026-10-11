package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// PreviewedCredential is one credential PresentCredentials would present.
type PreviewedCredential struct {
	// QueryID is the DCQL Credential Query it answers.
	QueryID string

	// Credential is the held credential that would be presented.
	Credential HeldCredential

	// Claims are the claim paths the query selects (OID4VP §6.4.1): the
	// selectively disclosable claims that would be disclosed — for an
	// mdoc, every element presented. Claims the issuer didn't make
	// selectively disclosable (an SD-JWT VC's vct, iss, cnf, or any
	// other always-visible claim) are seen by every Verifier regardless.
	Claims []dcql.Path

	// AlwaysDisclosed are an SD-JWT VC's claims the issuer didn't make
	// selectively disclosable, which every presentation of it discloses
	// whatever the selection: the issuer-signed payload's plaintext
	// members, the registered JWT and SD-JWT VC ones (iss, vct, cnf,
	// iat, nbf, exp, status, jti) aside. Show them with Claims. None for
	// an mdoc, whose every element is selectively disclosed.
	AlwaysDisclosed []dcql.Path
}

// PreviewPresentation reports what PresentCredentials would present for
// query from candidates — which credential answers each Credential
// Query, and exactly which claims it would disclose, respecting
// claim_sets and credential_sets — without presenting anything, so a
// Wallet can show the holder before asking for consent. It makes the
// same choices PresentCredentials does, through the same matching
// (MatchDCQLQuery) and claim selection. Credentials are ordered by
// QueryID.
func PreviewPresentation(ctx context.Context, query dcql.Query, candidates []HeldCredential, trustedAuthorities dcql.TrustedAuthoritiesChecker) ([]PreviewedCredential, error) {
	matches, err := MatchDCQLQuery(ctx, query, candidates, trustedAuthorities)
	if err != nil {
		return nil, fmt.Errorf("wallet: preview presentation: %w", err)
	}
	byID := make(map[string]dcql.CredentialQuery, len(query.Credentials))
	for _, cq := range query.Credentials {
		byID[cq.ID] = cq
	}
	ids := make([]string, 0, len(matches))
	for id := range matches {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var preview []PreviewedCredential
	for _, id := range ids {
		for _, held := range matches[id] {
			paths, err := selectedClaimPaths(held, byID[id])
			if err != nil {
				return nil, fmt.Errorf("wallet: preview presentation: credential query %q: %w", id, err)
			}
			preview = append(preview, PreviewedCredential{QueryID: id, Credential: held, Claims: paths, AlwaysDisclosed: alwaysDisclosed(held)})
		}
	}
	return preview, nil
}

// registeredClaims are an SD-JWT VC's registered members: about the
// credential, not its holder, and shown to a holder as its type and
// issuer, not as disclosed claims.
var registeredClaims = map[string]bool{
	"iss": true, "vct": true, "vct#integrity": true, "cnf": true, "iat": true, "nbf": true, "exp": true, "status": true, "jti": true,
	"_sd": true, "_sd_alg": true,
}

// alwaysDisclosed is held's plaintext claim paths, for an SD-JWT VC.
func alwaysDisclosed(held HeldCredential) []dcql.Path {
	if held.Format != sdjwtvc.CredentialFormat {
		return nil
	}
	pres, err := sdjwtvc.Parse(held.Credential)
	if err != nil {
		return nil
	}
	_, raw, err := jose.DecodeUnverifiedMax(pres.IssuerJWT, sdjwtvc.MaxBytes)
	if err != nil {
		return nil
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	var out []dcql.Path
	keys := slices.Sorted(maps.Keys(payload))
	for _, k := range keys {
		if registeredClaims[k] {
			continue
		}
		out = append(out, plaintextPaths(dcql.Path{dcql.PathKey(k)}, payload[k])...)
	}
	return out
}

// plaintextPaths are the plaintext leaves of v, at path: a nested object
// contributes its own plaintext members (its _sd digests are disclosed
// only when selected), anything else is disclosed whole.
func plaintextPaths(path dcql.Path, v any) []dcql.Path {
	obj, ok := v.(map[string]any)
	if !ok {
		return []dcql.Path{path}
	}
	var out []dcql.Path
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		if k == "_sd" {
			continue
		}
		child := append(slices.Clone(path), dcql.PathKey(k))
		out = append(out, plaintextPaths(child, obj[k])...)
	}
	return out
}
