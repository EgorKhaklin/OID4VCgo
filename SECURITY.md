# Security Policy

OID4VCgo implements OpenID4VCI + OpenID4VP under the HAIP 1.0 profile —
protocol code intended to run in high-assurance, security-critical
deployments (digital identity wallets, credential issuers and verifiers).
If you believe you've found a vulnerability (a protocol violation, a
cryptographic weakness, an authentication/authorization bypass, or
anything else with security impact), please report it privately rather
than opening a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab on
this repository and select **Report a vulnerability**. This creates a
private advisory visible only to maintainers until a fix is ready, rather
than a public issue.

If private reporting isn't available for any reason, open a regular issue
asking a maintainer to open a private channel — please don't include
vulnerability details in a public issue.

## Supported versions

OID4VCgo is under early active development and pre-1.0 (APIs may still
change) — see the [latest release](https://github.com/IDFoundry/OID4VCgo/releases/latest)
for the current tag. Reports against `main` or the latest tag are the
ones we can act on.

## Certificate revocation

A verified X.509 chain says nothing about a certificate its CA has since
revoked. The verifier's issuer trust checks revocation:
`verifier.X5CIssuerKeyResolver` and `verifier.X5ChainIssuerKeyResolver`
require a `Revocation` (a `certrevocation.Checker`) and accept a
credential only through a verified path from its issuer's certificate
to a trust anchor on which no certificate is revoked. Supply your CAs'
CRLs with `certrevocation.CRLs{Lists: ...}`: fetch each CA's CRL from
the distribution point its certificates name (ISO/IEC 18013-5 Annex B
makes one mandatory for an IACA's), keep the parsed lists in memory and
refresh them before their nextUpdate. A missing or stale CRL fails
closed. `certrevocation.NoCheck{}` declines the check explicitly, for
short-lived certificates or a trust framework that removes compromised
issuers from the anchor set itself.

Every other X.509 trust decision can check revocation too, through an
optional `certrevocation.Checker` beside the roots it applies to. Unlike
the verifier's issuer trust, these are opt-in: a nil Checker checks
nothing, and the certificate is trusted from its chain and validity
period alone. Each role is configured on its own, since `CRLs` fails
closed for a CA it has no current list from and an ecosystem may publish
CRLs for some roles and not others:

- a wallet's issuer trust on receipt
  (`wallet.VerifyIssuedCredentialParams.IssuerRevocation`,
  `walletflow.Config.IssuerRevocation`);
- a Verifier's request-signing certificate
  (`wallet.X5CVerifierRoots.Revocation`);
- signed issuer metadata (`wallet.Config.IssuerMetadataRevocation`,
  `walletflow.Config.IssuerMetadataRevocation`);
- a registrar's certificate (`registration.Registrars.Revocation`,
  `walletflow.Config.RegistrarRevocation`);
- an mdoc reader's certificate (`proximity.ReaderTrust.Revocation`,
  `mdocdcapi.ReaderTrust.Revocation`,
  `walletflow.Config.MdocReaderRevocation`);
- a proximity reader's document signer
  (`proximity.WithIssuerRevocation`);
- a status list signer (`statuslist.VerifyOptions.Revocation`,
  `walletflow.Config.StatusRevocation`; `verifier.RequireValidStatus`
  passes it on from the `statuslist.Checker` it's given);
- a key attestation's or jwt proof's certificate, at the issuer
  (`issuer.X5CAttestationVerifier.Revocation`,
  `issuer.X5CProofBindingKeyResolver.Revocation`).

The mobile library exposes them as the wallet's and reader's `crls` and
`revocation` configuration, with `SetCRLs` to replace the lists before
they expire (`mobile/ABI.md`). `dcql.AKITrustedAuthoritiesChecker`
checks none of its own: the verifier hands it the path its issuer key
resolver already checked. A Wallet Attestation's signer is verified by
FAPIgo's server (`server.X5CAttesterChain`), which doesn't check
revocation.

## What to include

- The affected package/file and, if possible, a minimal reproduction.
- The specific OID4VCI / OID4VP / HAIP / FAPI 2.0 requirement or security
  property you believe is violated (a spec section reference helps — see
  [SPECIFICATIONS.md](SPECIFICATIONS.md) for exact versions).
- Whether the issue is exploitable against a default configuration or
  requires a specific, non-default setup.

## Response

We'll acknowledge reports and work with you on a fix and coordinated
disclosure timeline before any public advisory is published.
