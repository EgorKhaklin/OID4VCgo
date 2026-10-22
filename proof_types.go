package oid4vci

// Proof type identifiers (Appendix F). Only the two OID4VCgo's
// credential formats actually use are defined here — di_vp (W3C VCDM)
// is out of scope; see SPECIFICATIONS.md.
const (
	// ProofTypeJWT is the "jwt" proof type (Appendix F.1): a JWT proves
	// possession of the key the issued Credential is bound to.
	ProofTypeJWT = "jwt"

	// ProofTypeAttestation is the "attestation" proof type (Appendix
	// F.3): a Key Attestation JWT conveys attested keys without itself
	// proving possession of any one of them.
	//
	// Nor does it name an audience: its only binding to the Credential
	// Issuer it's sent to is its nonce, the c_nonce from that issuer's
	// Nonce Endpoint, which anyone can call without authenticating. So
	// a Credential Issuer the Wallet talks to can fetch a c_nonce from
	// another issuer's Nonce Endpoint, hand it to the Wallet as its
	// own, and relay the key attestation the Wallet returns to that
	// other issuer, which accepts it as if the Wallet had sent it.
	// Where the deployment chooses proof_types_supported, prefer
	// ProofTypeJWT with a key_attestation header (Appendix D.1, F.1):
	// the proof itself is signed by an attested key and names the
	// issuer in aud.
	ProofTypeAttestation = "attestation"
)
