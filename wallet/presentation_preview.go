package wallet

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
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

	// AlwaysDisclosed are the SD-JWT VC claims this presentation
	// discloses beyond Claims, which the Verifier receives whatever the
	// selection: the claims the issuer didn't make selectively
	// disclosable, and the plaintext members of a disclosed object a
	// claim in Claims sits within. The registered JWT and SD-JWT VC
	// claims (iss, vct, cnf, iat, nbf, exp, status, jti) aside. Show
	// them with Claims. None for an mdoc, whose every element is
	// selectively disclosed.
	AlwaysDisclosed []dcql.Path

	// Retained are the Claims the Verifier says it intends to keep: an
	// mdoc's elements its query marks intent_to_retain (OpenID4VP
	// Appendix B.2.4). Show them to the holder with Claims.
	Retained []dcql.Path
}

// retainedClaims are the paths among selected that cq marks
// intent_to_retain.
func retainedClaims(cq dcql.CredentialQuery, selected []dcql.Path) []dcql.Path {
	var retained []dcql.Path
	for _, cl := range cq.Claims {
		if cl.IntentToRetain == nil || !*cl.IntentToRetain {
			continue
		}
		if slices.ContainsFunc(selected, func(p dcql.Path) bool { return slices.Equal(p, cl.Path) }) {
			retained = append(retained, cl.Path)
		}
	}
	return retained
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
			preview = append(preview, PreviewedCredential{QueryID: id, Credential: held, Claims: paths, AlwaysDisclosed: alwaysDisclosed(held, paths), Retained: retainedClaims(byID[id], paths)})
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

// alwaysDisclosed is what presenting held for paths discloses beyond
// paths themselves, for an SD-JWT VC: every claim the Verifier would
// receive, from the Disclosures a presentation for paths sends resolved
// against the payload, that no path covers. That's the claims the
// issuer didn't make selectively disclosable, and the plaintext
// members of a disclosed object a path selects within (RFC 9901 lets an
// issuer mix the two: selecting address.street sends the address
// Disclosure, and with it address.country).
func alwaysDisclosed(held HeldCredential, paths []dcql.Path) []dcql.Path {
	if held.Format != sdjwtvc.CredentialFormat {
		return nil
	}
	pres, hashAlg, _, err := resolveHeldSDJWTVC(held.Credential)
	if err != nil {
		return nil
	}
	payload, err := rawSDJWTVCPayload(pres)
	if err != nil {
		return nil
	}
	selected, err := sdjwtvc.SelectDisclosuresAt(payload, hashAlg, pres.Disclosures, sdjwtvcDisclosurePaths(paths))
	if err != nil {
		return nil
	}
	revealed, err := sdjwtvc.ResolveDisclosures(payload, hashAlg, selected)
	if err != nil {
		return nil
	}
	var out []dcql.Path
	for _, k := range slices.Sorted(maps.Keys(revealed)) {
		if registeredClaims[k] {
			continue
		}
		for _, leaf := range plaintextPaths(dcql.Path{dcql.PathKey(k)}, revealed[k]) {
			if !coveredBy(leaf, paths) {
				out = append(out, leaf)
			}
		}
	}
	return out
}

// coveredBy reports whether one of paths selects leaf, or something
// within it: one is a prefix of the other, a wildcard matching any
// element.
func coveredBy(leaf dcql.Path, paths []dcql.Path) bool {
	for _, p := range paths {
		n := min(len(p), len(leaf))
		match := true
		for i := range n {
			a, b := p[i], leaf[i]
			switch {
			case a.IsWildcard() || b.IsWildcard():
			case a.IsKey() && b.IsKey() && a.Key() == b.Key():
			case a.IsIndex() && b.IsIndex() && a.Index() == b.Index():
			default:
				match = false
			}
			if !match {
				break
			}
		}
		if match {
			return true
		}
	}
	return false
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
