// Package certrevocation checks whether an X.509 certificate a relying
// party is about to trust has been revoked by the CA that issued it.
//
// A verified certificate chain says only that a trusted CA issued each
// certificate and that each is inside its validity period. It says
// nothing about a certificate the CA has since revoked: a document
// signer or SD-JWT VC issuer whose key was stolen keeps signing
// credentials a chain check accepts until its certificate expires.
// Revocation information closes that gap. ISO/IEC 18013-5 has every
// IACA-issued certificate name a CRL distribution point (Annex B, B.1)
// and profiles the CRL itself (B.2), and expects a reader to hold
// current revocation information for the document signers it trusts
// (§12.8.4 of the second edition). HAIP 1.0 and OpenID4VP leave X.509
// revocation to the trust framework the verifier operates under.
//
// # Checker
//
// Checker is the one interface: given a verified chain, leaf first and
// ending at the trust anchor, and the instant of the verification, it
// returns nil when no certificate below the anchor has been revoked.
// The anchor itself is never checked: a relying party distrusts an
// anchor by removing it from its trust anchor set, not by asking it.
// The exception is a leaf pinned as an anchor, verified as a path of
// itself alone: CRLs checks it against its CA's CRL, which needs that
// CA's certificate in CRLs.Issuers.
//
// CRLs implements Checker with Certificate Revocation Lists (RFC 5280
// §5) the caller supplies. It does no fetching of its own: a
// deployment downloads each CA's CRL from the distribution point its
// certificates name, keeps the parsed lists in memory and refreshes
// them in the background before their nextUpdate. A missing or stale
// list fails closed: the certificate is refused, with ErrNoCurrentCRL,
// rather than accepted unchecked. A revoked certificate is refused with
// ErrRevoked.
//
// Refresher does that fetching for CRLs served over http or https: it
// fetches the distribution points the deployment configures, from
// public addresses only by default, keeps the last good list from each
// and replaces it only with one a configured CA signed that isn't
// older, so a failed or replayed fetch can't evict or roll back a good
// list. URLIssuers binds each URL to its CA, Floors and OnAccept carry
// the rollback floor across a restart, and RequireHTTPS refuses plain
// http distribution points. Its Run loop refreshes each list well before its nextUpdate,
// in a goroutine the caller starts; Refresher.Checker is the CRLs to
// check against. On a phone, the operating system's background
// scheduler should drive refreshes instead, handing the lists to the
// mobile library's SetCRLs.
//
// NoCheck declines checking revocation at all, as a visible line of
// code rather than a field left unset. OCSP (RFC 6960), or any other
// source of revocation status, can implement Checker; this package
// ships none.
//
// # Where it's used
//
// verifier.X5CIssuerKeyResolver and verifier.X5ChainIssuerKeyResolver
// require a Checker (their Revocation field) and apply it to every
// verified path from a credential's issuer certificate to a trust
// anchor: a credential is accepted only through a path no revoked
// certificate is on.
//
// Every other X.509 trust decision takes an optional Checker beside the
// roots it applies to, nil checking nothing: a wallet's issuer trust
// (wallet.VerifyIssuedCredentialParams.IssuerRevocation), a Verifier's
// certificate (wallet.X5CVerifierRoots.Revocation), signed issuer
// metadata (wallet.Config.IssuerMetadataRevocation), registrars
// (registration.Registrars), mdoc readers (proximity.ReaderTrust,
// mdocdcapi.ReaderTrust), a proximity reader's document signers
// (proximity.WithIssuerRevocation), status list signers
// (statuslist.VerifyOptions.Revocation), and key attestations and jwt
// proofs at the issuer (issuer.X5CAttestationVerifier,
// issuer.X5CProofBindingKeyResolver). walletflow.Config has one field
// per role, since CRLs fails closed for a CA it has no list from.
package certrevocation
