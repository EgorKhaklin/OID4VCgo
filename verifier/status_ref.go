package verifier

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListRef returns the Token Status List reference vc carries, in
// one form whichever format it is: an SD-JWT VC's "status" claim or an
// mdoc's MSO status. cwt reports which Status List Token form to fetch
// for it — CWT for an mdoc, JWT for an SD-JWT VC — as
// statuslist.Checker.Check takes it. ok is false when vc has no status
// list reference; err is set when it has a malformed one, or a status
// mechanism this package can't check (an mdoc identifier list) — so a
// caller that checks status when ok doesn't skip it.
//
//	ref, cwt, ok, err := vc.StatusListRef()
//	if err == nil && ok {
//		err = checker.RequireValid(ctx, ref, cwt)
//	}
//	if err != nil {
//		// refuse vc: revoked, suspended, or its status unreadable
//	}
//
// RequireValidStatus does this for every credential in an answer, as a
// TransactionsConfig.Accept.
func (vc VerifiedCredential) StatusListRef() (ref statuslist.StatusListRef, cwt, ok bool, err error) {
	if vc.MdocStatus != nil {
		sl := vc.MdocStatus.StatusList
		if sl == nil {
			if vc.MdocStatus.IdentifierList != nil {
				// A status this package can't check isn't "no status":
				// read as one, a revoked mdoc would pass.
				return statuslist.StatusListRef{}, false, false, fmt.Errorf("verifier: the mdoc's status is an identifier list, which isn't supported")
			}
			return statuslist.StatusListRef{}, false, false, nil
		}
		return statuslist.StatusListRef{Idx: sl.Idx, URI: sl.URI}, true, true, nil
	}
	status, present := vc.Claims["status"].(map[string]any)
	if !present {
		return statuslist.StatusListRef{}, false, false, nil
	}
	if ref, err = statuslist.ParseStatusClaim(status); err != nil {
		return statuslist.StatusListRef{}, false, false, err
	}
	return ref, false, true, nil
}

// RequireValidStatus is a TransactionsConfig.Accept that checks the
// status of every credential in an answer that carries a status list
// reference, with checker: an answer is refused when any of them isn't
// VALID (statuslist.NotValidError), when a status can't be read, or
// when a reference is malformed or uses a mechanism this package can't
// check. A credential with no status reference passes: it has no
// status to check.
//
// An SD-JWT VC's Status List Token must be signed by its issuer: a
// certificate naming the credential's iss, or without one the URI its
// own certificate names (statuslist.VerifyOptions.Issuer), so another
// issuer's certificate under the same roots can't decide its status.
// Where status lists come from a separate Status Issuer, use
// RequireValidStatusFrom.
func RequireValidStatus(checker statuslist.Checker) func(ctx context.Context, id string, result VerifyResponseResult) error {
	return RequireValidStatusFrom(checker, nil)
}

// StatusIssuerPolicy decides whether leaf, the chain-verified
// certificate that signed a Status List Token, belongs to a Status
// Issuer trusted to sign issuer's status lists: nil to accept it, an
// error to refuse. issuer is the credential's (its iss, or the URI its
// own certificate names), so a Status Issuer can be accepted for some
// issuers and not others.
type StatusIssuerPolicy func(issuer string, leaf *x509.Certificate, chains [][]*x509.Certificate) error

// RequireValidStatusFrom is RequireValidStatus for deployments whose
// status lists may be signed by a separate Status Issuer on the
// credential issuer's behalf (draft-ietf-oauth-status-list): an SD-JWT
// VC's Status List Token is accepted when its signer is the
// credential's issuer, as RequireValidStatus requires, or a Status
// Issuer statusIssuers accepts for that issuer. Anyone else under the
// roots is refused. checker.Options.LeafPolicy, if set, still applies
// to every signer. A nil statusIssuers is RequireValidStatus.
func RequireValidStatusFrom(checker statuslist.Checker, statusIssuers StatusIssuerPolicy) func(ctx context.Context, id string, result VerifyResponseResult) error {
	return func(ctx context.Context, _ string, result VerifyResponseResult) error {
		for _, vc := range result.Credentials {
			ref, cwt, ok, err := vc.StatusListRef()
			if err == nil && ok {
				c := checker
				if !cwt {
					// Its status list is its issuer's, or its Status
					// Issuer's, to sign.
					c.Options = statusOptionsFor(checker.Options, vc.issuerName(), statusIssuers)
				}
				err = c.RequireValid(ctx, ref, cwt)
			}
			if err != nil {
				return fmt.Errorf("verifier: credential status: %w", err)
			}
		}
		return nil
	}
}

// statusOptionsFor is opts for checking issuer's status list: signed by
// issuer, or with statusIssuers, by issuer or a Status Issuer it
// accepts for issuer.
func statusOptionsFor(opts statuslist.VerifyOptions, issuer string, statusIssuers StatusIssuerPolicy) statuslist.VerifyOptions {
	if statusIssuers == nil || issuer == "" {
		opts.Issuer = issuer
		return opts
	}
	base := opts.LeafPolicy
	opts.LeafPolicy = func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if base != nil {
			if err := base(leaf, chains); err != nil {
				return err
			}
		}
		if certchain.CheckIssuerName(leaf, issuer) == nil {
			return nil
		}
		if err := statusIssuers(issuer, leaf, chains); err != nil {
			return fmt.Errorf("neither the credential's issuer %q nor a Status Issuer for it: %w", issuer, err)
		}
		return nil
	}
	// A Status Issuer's token may carry its own iss.
	opts.Issuer = ""
	return opts
}

// issuerName is an SD-JWT VC's issuer, for its status list: its iss,
// or without one the URI its x5c leaf names, which is then the issuer.
// "" when it has neither, and its status list isn't bound to it.
func (vc VerifiedCredential) issuerName() string {
	if iss, ok := vc.Claims["iss"].(string); ok && iss != "" {
		return iss
	}
	if len(vc.IssuerChain) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(vc.IssuerChain[0])
	if err != nil || len(leaf.URIs) == 0 {
		return ""
	}
	return leaf.URIs[0].String()
}
