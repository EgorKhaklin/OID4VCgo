package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/dpop"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const testHTU = "https://issuer.example.com/token"

// fakeReplayChecker is an in-memory dpop.ReplayChecker for tests.
type fakeReplayChecker struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newFakeReplayChecker() *fakeReplayChecker { return &fakeReplayChecker{seen: map[string]bool{}} }

func (f *fakeReplayChecker) UseOnce(_ context.Context, jti string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen[jti] {
		return fakeErr("jti already used")
	}
	f.seen[jti] = true
	return nil
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// testWallet builds a real *wallet.Wallet whose only job in these
// tests is producing real DPoP proofs via GenerateDPoPProof — the
// exported primitive whose own doc comment names exactly this reuse
// case.
func testWallet(t *testing.T, now time.Time) *wallet.Wallet {
	t.Helper()
	w, err := wallet.New(wallet.Config{
		Assurance:       wallet.AssuranceDevelopment,
		ProofSigningAlg: jose.ES256,
		Fetch:           fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second},
	}, wallet.Dependencies{
		HTTP:   http.DefaultClient,
		Clock:  wallet.ClockFunc(func() time.Time { return now }),
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}
	return w
}

func mustJWK(t *testing.T, key *ecdsa.PrivateKey) jwk.JWK {
	t.Helper()
	k, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	return k
}

// mustPrivateJWK encodes key as a JWK including its private "d".
func mustPrivateJWK(t *testing.T, key *ecdsa.PrivateKey) jwk.JWK {
	t.Helper()
	k, err := jwk.MarshalPrivate(key)
	if err != nil {
		t.Fatalf("jwk.MarshalPrivate: %v", err)
	}
	return k
}

// TestVerifyAcceptsWalletGeneratedProof is the real round trip: a
// genuine DPoP proof from wallet.GenerateDPoPProof, verified by this
// package's own Verify — proving the two independently-built halves
// (client-side generation, server-side verification) agree on the wire
// format, the same discipline every other cross-package claim in this
// repo is held to.
func TestVerifyAcceptsWalletGeneratedProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)

	proof, err := w.GenerateDPoPProof(key, "POST", testHTU, "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	verified, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: testHTU,
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.IssuedAt.Unix() != now.Unix() {
		t.Errorf("IssuedAt = %v, want %v", verified.IssuedAt, now)
	}
	wireJWK, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	wantThumbprint, err := wireJWK.Thumbprint()
	if err != nil {
		t.Fatalf("compute expected thumbprint: %v", err)
	}
	if verified.Thumbprint != wantThumbprint {
		t.Errorf("Thumbprint = %q, want %q", verified.Thumbprint, wantThumbprint)
	}
}

func TestVerifyAcceptsMatchingNonce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)

	proof, err := w.GenerateDPoPProof(key, "POST", testHTU, "server-nonce", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	verified, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: testHTU,
		Now: now, MaxProofAge: time.Minute, RequiredNonce: "server-nonce", Replay: newFakeReplayChecker(),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Nonce != "server-nonce" {
		t.Errorf("Nonce = %q, want server-nonce", verified.Nonce)
	}
}

func TestVerifyIgnoresQueryAndFragmentInURL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)

	// GenerateDPoPProof signs whatever htu it's given verbatim — the
	// caller (wallet.RequestPreAuthorizedCodeToken) is the one that
	// strips query/fragment before calling it. This test signs a htu
	// that already carries a query/fragment to confirm Verify itself
	// also ignores them (RFC 9449 §4.3), not just that a well-behaved
	// caller never sends one.
	proof, err := w.GenerateDPoPProof(key, "POST", testHTU+"?a=b#frag", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: testHTU,
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyAllowsClockSkew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", testHTU, "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: testHTU,
		Now: now.Add(-10 * time.Second), MaxProofAge: time.Minute, MaxClockSkew: 30 * time.Second,
		Replay: newFakeReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsReplayedJTI(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	proof, err := w.GenerateDPoPProof(testP256Key(t), "POST", testHTU, "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	replay := newFakeReplayChecker()
	req := dpop.VerifyRequest{
		Proof: proof, Method: "POST", URL: testHTU,
		Now: now, MaxProofAge: time.Minute, Replay: replay,
	}
	if _, err := dpop.Verify(context.Background(), req); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), req); err == nil {
		t.Fatalf("second Verify (same jti) = nil error, want error")
	}
}

// tamperLastChar flips the second-to-last character of proof's own
// signature segment — not the very last one, since a fixed-width R||S
// signature's final base64url character can carry unused padding bits
// that legally decode to the same bytes (see internal/jose's own
// TestVerifyRejectsTampering for the same finding).
func tamperLastChar(proof string) string {
	r := []rune(proof)
	idx := len(r) - 2
	if r[idx] == 'x' {
		r[idx] = 'y'
	} else {
		r[idx] = 'x'
	}
	return string(r)
}

// TestVerifyRejects table-drives every rejection Verify itself detects
// from an otherwise-valid request/proof pair — each case starts from a
// known-good VerifyRequest and mutates exactly one thing about it.
func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w := testWallet(t, now)
	key := testP256Key(t)
	validProof, err := w.GenerateDPoPProof(key, "POST", testHTU, "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	nonceProof, err := w.GenerateDPoPProof(key, "POST", testHTU, "wrong-nonce", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	base := func() dpop.VerifyRequest {
		return dpop.VerifyRequest{
			Proof: validProof, Method: "POST", URL: testHTU,
			Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
		}
	}

	cases := map[string]func() dpop.VerifyRequest{
		"method mismatch": func() dpop.VerifyRequest {
			r := base()
			r.Method = "GET"
			return r
		},
		// HTTP methods are case-sensitive.
		"method differing in case": func() dpop.VerifyRequest {
			r := base()
			r.Method = "post"
			return r
		},
		"url mismatch": func() dpop.VerifyRequest {
			r := base()
			r.URL = "https://issuer.example.com/other"
			return r
		},
		"expired": func() dpop.VerifyRequest {
			r := base()
			r.Now = now.Add(2 * time.Minute)
			return r
		},
		"future iat": func() dpop.VerifyRequest {
			r := base()
			r.Now = now.Add(-time.Hour)
			return r
		},
		"nonce mismatch": func() dpop.VerifyRequest {
			r := base()
			r.Proof, r.RequiredNonce = nonceProof, "expected-nonce"
			return r
		},
		"missing nonce when required": func() dpop.VerifyRequest {
			r := base()
			r.RequiredNonce = "expected-nonce"
			return r
		},
		"tampered signature": func() dpop.VerifyRequest {
			r := base()
			r.Proof = tamperLastChar(validProof)
			return r
		},
		"missing replay checker": func() dpop.VerifyRequest {
			r := base()
			r.Replay = nil
			return r
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := dpop.Verify(context.Background(), build()); err == nil {
				t.Fatalf("Verify(%s) = nil error, want error", name)
			}
		})
	}
}

// TestVerifyRejectsMalformedProof table-drives every rejection that
// depends on the proof's own header/payload shape rather than the
// VerifyRequest around it — these bypass wallet.GenerateDPoPProof
// (which always builds a well-formed proof) and sign a
// deliberately-malformed one directly via jose.Sign.
func TestVerifyRejectsMalformedProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	validPayload := []byte(`{"jti":"j1","htm":"POST","htu":"` + testHTU + `","iat":1700000000}`)

	cases := map[string]struct {
		header  map[string]any
		payload []byte
	}{
		"wrong typ": {
			header:  map[string]any{"typ": "wrong+jwt", "jwk": mustJWK(t, key)},
			payload: validPayload,
		},
		"missing jwk": {
			header:  map[string]any{"typ": "dpop+jwt"},
			payload: validPayload,
		},
		"missing jti": {
			header:  map[string]any{"typ": "dpop+jwt", "jwk": mustJWK(t, key)},
			payload: []byte(`{"htm":"POST","htu":"` + testHTU + `","iat":1700000000}`),
		},
		// RFC 9449 §4.3: the jwk header must not contain a private key.
		"jwk carries the private key": {
			header:  map[string]any{"typ": "dpop+jwt", "jwk": mustPrivateJWK(t, key)},
			payload: validPayload,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			proof, err := jose.Sign(jose.ES256, key, tc.header, tc.payload)
			if err != nil {
				t.Fatalf("jose.Sign: %v", err)
			}
			if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
				Proof: proof, Method: "POST", URL: testHTU,
				Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
			}); err == nil {
				t.Fatalf("Verify(%s) = nil error, want error", name)
			}
		})
	}
}

// signedProof signs a DPoP proof whose payload carries jti and nonce
// (omitted when "") for testHTU, issued at now.
func signedProof(t *testing.T, key *ecdsa.PrivateKey, jti, nonce string, now time.Time) string {
	t.Helper()
	claims := map[string]any{"jti": jti, "htm": "POST", "htu": testHTU, "iat": now.Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dpop+jwt", "jwk": mustJWK(t, key)}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return proof
}

// TestVerifyBoundsWhatReplayRemembers: a jti over MaxJTILength is
// refused before the replay check, and an accepted one reaches it only
// as its fixed-size digest, so a client can't make the replay record
// keep tens of kilobytes per proof.
func TestVerifyBoundsWhatReplayRemembers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	replay := newFakeReplayChecker()
	req := dpop.VerifyRequest{Method: "POST", URL: testHTU, Now: now, MaxProofAge: time.Minute, Replay: replay}

	for _, n := range []int{47000, dpop.MaxJTILength + 1} {
		req.Proof = signedProof(t, key, strings.Repeat("A", n), "", now)
		if _, err := dpop.Verify(context.Background(), req); err == nil {
			t.Fatalf("Verify with a %d-byte jti = nil error, want it refused", n)
		}
	}
	if len(replay.seen) != 0 {
		t.Fatalf("replay record holds %d entries after refused proofs, want 0", len(replay.seen))
	}

	jti := strings.Repeat("B", dpop.MaxJTILength)
	req.Proof = signedProof(t, key, jti, "", now)
	if _, err := dpop.Verify(context.Background(), req); err != nil {
		t.Fatalf("Verify with a %d-byte jti: %v", dpop.MaxJTILength, err)
	}
	if !replay.seen[dpop.JTIDigest(jti)] || len(replay.seen) != 1 {
		t.Fatalf("replay record = %v, want only the jti's digest", replay.seen)
	}
	if got := len(dpop.JTIDigest(jti)); got != 43 {
		t.Fatalf("len(JTIDigest) = %d, want 43", got)
	}
}

// TestVerifyChecksNonceBeforeReplay: CheckNonce sees the proof's nonce,
// and a proof it refuses is never recorded, so it can't use up the jti.
func TestVerifyChecksNonceBeforeReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	replay := newFakeReplayChecker()
	var seen string
	refuse := true
	req := dpop.VerifyRequest{
		Proof: signedProof(t, key, "j1", "n1", now), Method: "POST", URL: testHTU,
		Now: now, MaxProofAge: time.Minute, Replay: replay,
		CheckNonce: func(_ context.Context, nonce string) error {
			seen = nonce
			if refuse {
				return fakeErr("use a fresh nonce")
			}
			return nil
		},
	}
	if _, err := dpop.Verify(context.Background(), req); err == nil {
		t.Fatal("Verify with a refused nonce = nil error, want error")
	}
	if seen != "n1" {
		t.Fatalf("CheckNonce saw %q, want %q", seen, "n1")
	}
	if len(replay.seen) != 0 {
		t.Fatalf("replay record holds %d entries after a refused nonce, want 0", len(replay.seen))
	}
	refuse = false
	if _, err := dpop.Verify(context.Background(), req); err != nil {
		t.Fatalf("Verify of the same proof once the nonce is accepted: %v", err)
	}
}
