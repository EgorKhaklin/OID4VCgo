package walletflow

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Config configures a Wallet.
type Config struct {
	// ClientID and RedirectURI are the wallet's registration with
	// Authorization Servers: the client_id its Wallet Attestations
	// name, and where the authorization code grant redirects back to.
	// ClientID is REQUIRED to authenticate with a Wallet Attestation,
	// and RedirectURI for the authorization code grant; a wallet
	// receiving credentials only from pre-authorized codes redeemed
	// with no client authentication needs neither.
	ClientID    string
	RedirectURI string

	// IssuerRoots are the trust anchors for issuers: every received
	// credential must be signed by a certificate chaining to one of
	// them, or it's refused. REQUIRED for StartIssuance.
	IssuerRoots *x509.CertPool
	// IssuerLeafPolicy, if set, decides whether a certificate under
	// IssuerRoots may sign credentials
	// (wallet.VerifyIssuedCredentialParams.IssuerLeafPolicy): set it
	// where IssuerRoots also anchor another role, such as Verifiers.
	IssuerLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// StatusIssuers are the Status Issuers that may sign a credential
	// issuer's status lists on its behalf (draft-ietf-oauth-status-list):
	// credential issuer (an SD-JWT VC's iss) → the identifiers of its
	// Status Issuers, each recognized by a certificate under IssuerRoots
	// naming it (a uniformResourceIdentifier, or for a "dns:" one a
	// dNSName). CheckStatus otherwise accepts only a status list the
	// credential's issuer signed itself, with the credential's own key
	// or a certificate naming its iss, so another issuer under the same
	// roots can't decide its status. An mdoc's is bound as ISO/IEC
	// 18013-5 §12.3.6 says instead: under the Certificate its MSO's
	// status names, or else the CA that signed its document signer;
	// StatusIssuers, keyed by iss, doesn't apply to it.
	StatusIssuers map[string][]string

	// RequireIssuerName refuses a received SD-JWT VC whose iss its
	// signing certificate doesn't name
	// (wallet.VerifyIssuedCredentialParams.RequireIssuerName). SD-JWT VC
	// doesn't require them to correspond, so it's off by default: set
	// it where IssuerRoots certify several issuers, so none can issue in
	// another's name.
	RequireIssuerName bool

	// AllowForeignIss receives an SD-JWT VC whose iss isn't the
	// Credential Issuer Identifier it was requested from (the offer's
	// credential_issuer). By default one is refused, received, deferred
	// or refreshed (wallet.VerifyIssuedCredentialParams.CredentialIssuer):
	// IssuerRoots may certify several issuers, and an issuer the holder
	// was sent to could otherwise hand over another's credential, issued
	// for the holder's keys, as its own. A credential with no iss names
	// none to check. OpenID4VCI 1.0 §14.4 lets an issued credential name
	// its issuer differently from the Credential Issuer Identifier: set
	// it only for issuers that do, where IssuerRoots certify them alone.
	AllowForeignIss bool

	// IssuerMetadataRoots, IssuerMetadataLeafPolicy,
	// RequireSignedIssuerMetadata, RequireIssuerMetadataName and
	// MaxIssuerMetadataAge are the
	// Credential Issuer Metadata trust settings of wallet.Config: with
	// IssuerMetadataRoots set, signed metadata (OpenID4VCI §12.2.3, HAIP
	// 1.0 §4.1) is asked for and verified, and RequireSignedIssuerMetadata
	// refuses an issuer without it, before the holder authenticates or
	// enters a transaction code. See wallet.Config for each.
	IssuerMetadataRoots         *x509.CertPool
	IssuerMetadataLeafPolicy    func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	RequireSignedIssuerMetadata bool
	RequireIssuerMetadataName   bool
	MaxIssuerMetadataAge        time.Duration

	// IssuanceProfile is the profile issuance follows. The zero value,
	// ProfileOpenID4VCI, follows the issuer's and Authorization Server's
	// metadata; ProfileHAIP also refuses issuers outside HAIP 1.0.
	IssuanceProfile IssuanceProfile

	// VerifierTrust decides which Verifiers the wallet answers
	// (OpenID4VP 1.0 §5.9.3). REQUIRED for StartPresentation, and for a
	// signed request to StartDCAPIPresentation.
	VerifierTrust wallet.VerifierTrust

	// RegistrarRoots, if set, are the registrars whose registrations of
	// Verifiers the wallet checks (the registration package): a
	// request's registration, from its verifier_info, is reported with
	// what the request asks beyond it (Presentation.Registration).
	// Unset, registrations are ignored. They must anchor only
	// registrars: any end-entity certificate under them can register a
	// Verifier, so roots shared with Verifiers or Issuers would let them
	// register themselves. A registration signed with the Verifier's own
	// key is never accepted.
	RegistrarRoots *x509.CertPool
	// RegistrarLeafPolicy, if set, decides whether a certificate under
	// RegistrarRoots may sign registrations: an extended key usage or
	// certificate policy the ecosystem defines for registrars, say.
	RegistrarLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// MdocReaderRoots, if set, are the mdoc readers the wallet
	// recognizes when one signs an org-iso-mdoc request
	// (MdocPresentation.Reader) or an in-person one
	// (ProximityPresentation's reader). An unsigned or unrecognized
	// request is still answered if the holder agrees, shown by its
	// origin or as an unknown reader — unless RequireTrustedMdocReader.
	MdocReaderRoots *x509.CertPool
	// MdocReaderLeafPolicy, if set, decides whether a certificate under
	// MdocReaderRoots is a reader's: mdocdcapi.RequireReaderAuthenticationEKU
	// requires the ISO/IEC 18013-5 reader authentication extended key
	// usage, so a certificate issued under the same roots for another
	// role isn't taken for a reader.
	MdocReaderLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// RequireTrustedMdocReader refuses an org-iso-mdoc or in-person
	// request no reader under MdocReaderRoots signed, and nothing is
	// shown to the holder: StartMdocPresentation returns an error
	// wrapping ErrUntrustedVerifier, and an in-person session ends with
	// a ProximityEvent whose Err wraps it, sending the reader a
	// termination. It needs MdocReaderRoots.
	RequireTrustedMdocReader bool
	// ProximityDeviceAuth is how an in-person response authenticates the
	// mdoc (ISO/IEC 18013-5 §9.1.3). The zero value,
	// ProximityDeviceSignature, signs with the holder key.
	ProximityDeviceAuth ProximityDeviceAuth

	// RequireSignedDCAPIRequests refuses an unsigned OpenID4VP request
	// over the Digital Credentials API (StartDCAPIPresentation) with an
	// error wrapping ErrUntrustedVerifier, before the holder sees it: its
	// only identity is the origin the platform reports, which
	// VerifierTrust can't judge. HAIP 1.0 §5.2 requires a Wallet to
	// support unsigned requests, so set it only where every Verifier must
	// be one VerifierTrust accepts.
	RequireSignedDCAPIRequests bool

	// Locales are the holder's preferred languages (BCP 47 tags, most
	// preferred first), for the issuer's display metadata: sent as
	// Accept-Language when fetching it (OpenID4VCI 1.0 §12.2.2), and
	// used to pick among its entries. None means the issuer's entry
	// without a locale, else its first.
	Locales []string

	// RequestRefresh asks the Authorization Server, in the authorization
	// code flow, for a refresh token (the offline_access scope), so
	// Wallet.RefreshCredential can later replace a credential's copies
	// without the holder (OpenID4VCI 1.0 §13.5). The server must allow
	// the wallet that scope, or the authorization fails with
	// invalid_scope. In the pre-authorized code flow there's no scope to
	// ask with: a refresh token the server issues anyway is kept. The
	// refresh token and the wallet instance key are then kept in
	// Dependencies.Grants; without RequestRefresh, a refresh token is
	// discarded.
	RequestRefresh bool

	// CopyPolicy decides which copy of a credential a presentation uses
	// (OpenID4VCI 1.0: "a unique Credential per presentation or per
	// Verifier"). The zero value is CopyPerPresentation.
	CopyPolicy CopyPolicy

	// BatchSize is how many copies of each credential to request when
	// the issuer offers batch issuance, each bound to its own key, so
	// each presentation can use one no Verifier has seen. It's capped at
	// the issuer's batch_size. Zero means DefaultBatchSize; 1 requests
	// one copy.
	BatchSize int

	// Development relaxes what production requires, for a wallet
	// talking to services on this machine. Never set it in a wallet
	// that holders use, nor just to use memory stores: it also drops
	// the network protections below. It:
	//   - lets issuers, Authorization Servers, Verifiers and status
	//     lists be on loopback addresses, over http there too;
	//   - permits wallet.NoVerifierTrust as VerifierTrust;
	//   - makes requests through an ordinary HTTP client, which reaches
	//     private networks, instead of the hardened one;
	//   - skips the checks New makes at production assurance: Durable
	//     Authorizations (and Grants, with RequestRefresh), Keys
	//     declaring durable custody, Random crypto/rand, one pool per
	//     role (or leaf policies) — and fapigo/client's own production
	//     checks.
	Development bool

	// TLSPins, if set, pins hosts' certificates (see TLSPins) on the
	// HTTP client New builds when Dependencies.HTTP is nil, in
	// Development too. With Dependencies.HTTP set, New refuses them:
	// set TLSPins.VerifyConnection on that client's TLS configuration
	// instead.
	TLSPins TLSPins
}

// Dependencies are what the app supplies.
type Dependencies struct {
	// Keys holds the wallet's keys. REQUIRED. Production assurance
	// checks only that it declares durable custody
	// (keys.KeyCustodyAssurance) — it can't check where the keys are.
	// A wallet's holder keys belong in secure hardware that won't
	// export them (the Secure Enclave, StrongBox), needing the holder's
	// presence to present; that's the KeyStore's to provide.
	Keys        KeyStore
	Credentials CredentialStore // REQUIRED
	// Provider attests the wallet (Wallet Attestations) and its keys
	// (Key Attestations), for issuers that require them: HAIP 1.0's,
	// and any whose Authorization Server takes only a Wallet Attestation
	// or that sets key_attestations_required. nil means the wallet gives
	// neither, and receives credentials only from issuers that need
	// neither (OpenID4VCI 1.0 allows both to be left out). REQUIRED
	// under ProfileHAIP.
	Provider WalletProvider
	// Deferred keeps pending deferred credentials, so they can be polled
	// after a restart. nil means a MemoryDeferredStore.
	Deferred DeferredStore
	// Authorizations keeps the authorizations in progress, so the
	// redirect can complete one after a restart (ResumeIssuance). nil
	// means a MemoryAuthorizationStore. Receiving credentials at
	// production assurance (Config.Development false) needs a Durable
	// one, Keys that declare durable custody (keys.KeyCustodyAssurance),
	// and Random left nil or crypto/rand.Reader.
	Authorizations AuthorizationStore
	// Grants keeps refresh grants (Config.RequestRefresh). nil means a
	// MemoryGrantStore. Receiving credentials at production assurance
	// with RequestRefresh set needs a Durable one.
	Grants GrantStore

	// HTTP makes every request. nil means a client with a 10 s timeout
	// that, outside Development, is fapihttp's hardened one: it dials
	// only public addresses and follows no redirect. One set here should
	// be as careful: issuers' and Verifiers' endpoints come from offers
	// and requests anyone can make.
	HTTP *http.Client
	// Clock returns the current time. nil means time.Now.
	Clock func() time.Time
	// Random is the source of identifiers and protocol randomness. nil
	// means crypto/rand.
	Random io.Reader
}

// Wallet is a holder's wallet. Its methods are safe for concurrent use;
// each session they start is used by one goroutine at a time.
type Wallet struct {
	cfg  Config
	deps Dependencies
	core *wallet.Wallet

	mu       sync.Mutex
	deferred map[string]*Deferred // the pending ones handed out, by ID
	// liveKeys are the instance and DPoP keys open issuances hold, by
	// ID: how many hold each. Two issuances can hold one key (a resumed
	// authorization and the issuance that began it, or two resumes of
	// one redirect), and the first to close mustn't delete it.
	liveKeys map[string]int
	// resuming are the authorizations ResumeIssuance is completing, by
	// state: a second resume of one redirect waits for none.
	resuming map[string]bool
	// openGrants are the refresh grants open issuances hold, by ID: in
	// use until the issuance closes, however many credentials are stored
	// yet.
	openGrants map[string]bool
	authMu     sync.Mutex // serializes consuming authorizations
	// credMu serializes reading, changing and writing back a stored
	// credential: choosing and marking the copies a presentation uses,
	// recording a status, replacing a refreshed one, deleting one. It's
	// never held across a network request.
	credMu sync.Mutex
	// reservations are, by copy, the latest presentation reserving it
	// (reservedCopy.seq), under credMu: a presentation that isn't sent
	// undoes its reservation only when no other has reserved the copy
	// since, as that one may have been sent.
	reservations map[copyRef]uint64
	reserveSeq   uint64
	// grantMu serializes refreshes per refresh grant (grantLocks, by
	// grant ID), held across the refresh's requests.
	grantMu    sync.Mutex
	grantLocks map[string]*sync.Mutex
}

// CopyPolicy is which copy of a credential a presentation uses.
type CopyPolicy int

const (
	// CopyPerPresentation presents a copy no Verifier has seen, every
	// time: not even the same Verifier can link two presentations by the
	// credential. Copies run out fastest. It's the default.
	CopyPerPresentation CopyPolicy = iota
	// CopyPerVerifier presents a Verifier the copy it has seen before, if
	// any, else one no Verifier has seen: Verifiers can't link
	// presentations to each other, but one Verifier can recognise a
	// returning holder. Copies last as long as there are new Verifiers.
	CopyPerVerifier
)

// DefaultBatchSize is how many copies of a credential a wallet requests
// when Config.BatchSize is zero and the issuer offers batch issuance.
const DefaultBatchSize = 5

const (
	httpTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 20
)

// New returns a Wallet. Make one per set of stores and share it: a
// Wallet serializes its own use of them (choosing the copies a
// presentation uses, consuming an authorization, refreshing a grant), so
// two over the same Keys and Credentials don't coordinate, and could
// present the same copy twice, linking the presentations, or redeem the
// same refresh token twice, which an authorization server rotating
// refresh tokens answers by revoking the grant.
func New(cfg Config, deps Dependencies) (*Wallet, error) {
	if deps.Keys == nil || deps.Credentials == nil {
		return nil, errors.New("walletflow: Dependencies.Keys and Credentials are required")
	}
	if cfg.RequireTrustedMdocReader && cfg.MdocReaderRoots == nil {
		return nil, errors.New("walletflow: Config.RequireTrustedMdocReader needs MdocReaderRoots")
	}
	if err := cfg.validateChoices(); err != nil {
		return nil, err
	}
	if !cfg.Development {
		if err := checkRoleSeparation(cfg); err != nil {
			return nil, err
		}
	}
	if err := cfg.TLSPins.Validate(); err != nil {
		return nil, err
	}
	deps, err := withDefaultDependencies(cfg, deps)
	if err != nil {
		return nil, err
	}
	core, err := wallet.New(wallet.Config{
		Assurance: cfg.assurance(), ProofSigningAlg: oid4vci.ES256, VerifierTrust: cfg.VerifierTrust,
		RequireSignedDCAPIRequests: cfg.RequireSignedDCAPIRequests,
		IssuerMetadataRoots:        cfg.IssuerMetadataRoots, IssuerMetadataLeafPolicy: cfg.IssuerMetadataLeafPolicy,
		RequireSignedIssuerMetadata: cfg.RequireSignedIssuerMetadata,
		RequireIssuerMetadataName:   cfg.RequireIssuerMetadataName, MaxIssuerMetadataAge: cfg.MaxIssuerMetadataAge,
		Locales: cfg.Locales,
		Fetch: fapihttp.Config{
			MaxResponseBytes: maxResponseBytes, RequestTimeout: httpTimeout, MaxRedirects: 2,
			AllowLoopbackHosts: cfg.Development,
		},
	}, wallet.Dependencies{HTTP: deps.HTTP, Clock: wallet.ClockFunc(deps.Clock), Random: deps.Random})
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	w := &Wallet{
		cfg: cfg, deps: deps, core: core, deferred: map[string]*Deferred{}, liveKeys: map[string]int{}, resuming: map[string]bool{},
		openGrants: map[string]bool{}, grantLocks: map[string]*sync.Mutex{},
	}
	if err := w.checkReceivingAtNew(); err != nil {
		return nil, err
	}
	return w, nil
}

// withDefaultDependencies is deps with the wallet's own HTTP client,
// pinned to cfg.TLSPins, and in-memory stores and the system clock and
// randomness for those deps leaves nil. It refuses TLSPins alongside a
// caller's HTTP client, which they wouldn't apply to.
func withDefaultDependencies(cfg Config, deps Dependencies) (Dependencies, error) {
	if deps.HTTP == nil {
		client, err := defaultHTTPClient(cfg.Development, cfg.TLSPins)
		if err != nil {
			return deps, err
		}
		deps.HTTP = client
	} else if len(cfg.TLSPins) > 0 {
		return deps, errors.New("walletflow: Config.TLSPins applies to the wallet's own HTTP client, not Dependencies.HTTP: set TLSPins.VerifyConnection on that client's TLS configuration instead")
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.Random == nil {
		deps.Random = rand.Reader
	}
	if deps.Deferred == nil {
		deps.Deferred = NewMemoryDeferredStore()
	}
	if deps.Authorizations == nil {
		deps.Authorizations = NewMemoryAuthorizationStore()
	}
	if deps.Grants == nil {
		deps.Grants = NewMemoryGrantStore()
	}
	return deps, nil
}

// checkReceivingAtNew checks what receiving credentials needs in
// production now rather than when a holder first tries to receive one:
// checkProductionReceiving's checks, and a Durable Authorizations store
// when issuance redirects.
func (w *Wallet) checkReceivingAtNew() error {
	if w.cfg.Development || w.cfg.IssuerRoots == nil {
		return nil
	}
	if err := w.checkProductionReceiving(); err != nil {
		return err
	}
	if w.cfg.RedirectURI != "" && !w.deps.Authorizations.Durable() {
		return errors.New("walletflow: receiving credentials in production needs a Durable Dependencies.Authorizations, so an authorization survives the app being suspended")
	}
	return nil
}

// validateChoices refuses a Config field set to a value it has no
// meaning for, which would otherwise act as its default: an
// IssuanceProfile(9) as the less strict ProfileOpenID4VCI, say.
func (c Config) validateChoices() error {
	switch {
	case c.IssuanceProfile != ProfileOpenID4VCI && c.IssuanceProfile != ProfileHAIP:
		return fmt.Errorf("walletflow: Config.IssuanceProfile %d isn't a profile", c.IssuanceProfile)
	case c.CopyPolicy != CopyPerPresentation && c.CopyPolicy != CopyPerVerifier:
		return fmt.Errorf("walletflow: Config.CopyPolicy %d isn't a policy", c.CopyPolicy)
	case c.BatchSize < 0:
		return fmt.Errorf("walletflow: Config.BatchSize %d is negative", c.BatchSize)
	}
	return nil
}

// checkRoleSeparation refuses, in production, one certificate pool
// given to two roles unless both narrow their certificates by a leaf
// policy (an extended key usage, say): otherwise a Verifier's
// certificate under the shared pool could sign credentials the wallet
// accepts or an issuer's metadata, an issuer's pass for a trusted
// Verifier or mdoc reader, or a Verifier register itself. Pools are compared as wholes (CertPool
// can't be listed), so only the same pool is caught; the mobile façade,
// which has the certificates, also catches overlapping ones.
func checkRoleSeparation(c Config) error {
	type role struct {
		name      string
		pool      *x509.CertPool
		hasPolicy bool
	}
	roles := []role{
		{"IssuerRoots", c.IssuerRoots, c.IssuerLeafPolicy != nil},
		{"IssuerMetadataRoots", c.IssuerMetadataRoots, c.IssuerMetadataLeafPolicy != nil},
		{"RegistrarRoots", c.RegistrarRoots, c.RegistrarLeafPolicy != nil},
		{"MdocReaderRoots", c.MdocReaderRoots, c.MdocReaderLeafPolicy != nil},
	}
	if v, ok := c.VerifierTrust.(wallet.X5CVerifierRoots); ok {
		roles = append(roles, role{"VerifierTrust", v.Roots, v.LeafPolicy != nil})
	}
	for i, a := range roles {
		for _, b := range roles[i+1:] {
			if a.pool == nil || b.pool == nil || !a.pool.Equal(b.pool) {
				continue
			}
			for _, r := range []role{a, b} {
				if !r.hasPolicy {
					return fmt.Errorf("walletflow: %s and %s are the same certificate pool: give %s a leaf policy (an extended key usage) to tell its certificates apart, or use separate pools", a.name, b.name, r.name)
				}
			}
		}
	}
	return nil
}

func (c Config) assurance() wallet.AssuranceLevel {
	if c.Development {
		return wallet.AssuranceDevelopment
	}
	return wallet.AssuranceProduction
}

func (c Config) clientAssurance() client.AssuranceLevel {
	if c.Development {
		return client.AssuranceDevelopment
	}
	return client.AssuranceProduction
}

// Credentials returns every credential the wallet holds.
func (w *Wallet) Credentials(ctx context.Context) ([]StoredCredential, error) {
	creds, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list credentials: %w", err)
	}
	return creds, nil
}

// DeleteCredential deletes the credential id names, and every copy's
// holder key. Once no other credential uses its refresh grant, the
// refresh token is revoked at the Authorization Server (RFC 7009), best
// effort and only when it has a revocation endpoint, so the issuer's
// standing grant ends with it; then the grant and its instance key are
// deleted.
func (w *Wallet) DeleteCredential(ctx context.Context, id string) error {
	c, err := w.deleteCredential(ctx, id)
	if err != nil {
		return err
	}
	if err := w.releaseUnusedGrant(ctx, c.GrantID, c.ConfigurationID); err != nil {
		return fmt.Errorf("walletflow: delete credential's refresh grant: %w", err)
	}
	return nil
}

// deleteCredential deletes the credential id names and its copies'
// keys, and returns it.
func (w *Wallet) deleteCredential(ctx context.Context, id string) (StoredCredential, error) {
	w.credMu.Lock()
	defer w.credMu.Unlock()
	c, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: delete credential: %w", err)
	}
	if err := w.deps.Credentials.Delete(ctx, id); err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: delete credential: %w", err)
	}
	for _, cp := range c.AllCopies() {
		if err := w.deps.Keys.DeleteKey(ctx, cp.HolderKeyID); err != nil {
			return StoredCredential{}, fmt.Errorf("walletflow: delete credential's holder key: %w", err)
		}
	}
	return c, nil
}

// checkIssuance reports what StartIssuance needs that w lacks, whatever
// the offer: what the grant an offer has needs is checked once it's
// known (checkAuthorizationCode, chooseClientAuth).
func (w *Wallet) checkIssuance() error {
	switch {
	case w.cfg.IssuerRoots == nil:
		return errors.New("walletflow: Config.IssuerRoots is required to receive credentials")
	case w.cfg.IssuanceProfile == ProfileHAIP && (w.deps.Provider == nil || w.cfg.ClientID == ""):
		return errors.New("walletflow: Dependencies.Provider and Config.ClientID are required to receive credentials under ProfileHAIP")
	}
	if w.cfg.Development {
		return nil
	}
	return w.checkProductionReceiving()
}

// checkProductionReceiving is what receiving credentials needs in
// production: fapigo/client's production assurance, checked here first
// to say what to change.
func (w *Wallet) checkProductionReceiving() error {
	switch {
	case w.cfg.RequestRefresh && !w.deps.Grants.Durable():
		return errors.New("walletflow: refreshing credentials in production needs a Durable Dependencies.Grants, so a refresh token survives a restart")
	case !durableKeys(w.deps.Keys):
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Keys to declare durable custody (keys.KeyCustodyAssurance)")
	case w.deps.Random != rand.Reader:
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Random to be nil or crypto/rand.Reader")
	}
	return nil
}

// checkAuthorizationCode reports what the authorization code grant needs
// that w lacks, beyond checkIssuance: a redirect URI, and in production
// a Durable Authorizations store, so an authorization survives the app
// being suspended.
func (w *Wallet) checkAuthorizationCode() error {
	switch {
	case w.cfg.RedirectURI == "":
		return errors.New("walletflow: Config.RedirectURI is required to receive credentials with the authorization code grant")
	case !w.cfg.Development && !w.deps.Authorizations.Durable():
		return errors.New("walletflow: receiving credentials in production needs a Durable Dependencies.Authorizations, so an authorization survives the app being suspended")
	}
	return nil
}

// durableKeys reports whether ks declares it keeps its keys durably.
func durableKeys(ks KeyStore) bool {
	c, ok := ks.(keys.KeyCustodyAssurance)
	return ok && c.KeyCustody().Durable
}

// defaultHTTPClient is the client New uses when Dependencies.HTTP is
// nil. Outside Development it dials only public addresses, resolved
// once and checked at dial time, and follows no redirect: an offer's or
// a Verifier's endpoints can't point the wallet's requests into its own
// network. In Development, services on the machine or the local network
// are the point. Either checks pins, when there are any.
func defaultHTTPClient(development bool, pins TLSPins) (*http.Client, error) {
	var verify func(tls.ConnectionState) error
	if len(pins) > 0 {
		verify = pins.VerifyConnection
	}
	if development {
		if verify == nil {
			return &http.Client{Timeout: httpTimeout}, nil
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, VerifyConnection: verify}
		return &http.Client{Transport: transport, Timeout: httpTimeout}, nil
	}
	client, err := fapihttp.NewClient(fapihttp.TransportConfig{DialTimeout: httpTimeout, TLSHandshakeTimeout: httpTimeout, VerifyConnection: verify})
	if err != nil {
		return nil, fmt.Errorf("walletflow: http client: %w", err)
	}
	client.Timeout = httpTimeout
	return client, nil
}

// holdKey records that an open issuance holds key id.
func (w *Wallet) holdKey(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.liveKeys[id]++
}

// unholdKey records that an issuance no longer holds key id.
func (w *Wallet) unholdKey(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.liveKeys[id] <= 1 {
		delete(w.liveKeys, id)
	} else {
		w.liveKeys[id]--
	}
}

// keyHeld reports whether an open issuance holds key id.
func (w *Wallet) keyHeld(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.liveKeys[id] > 0
}
