package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// responseVector is a direct_post.jwt answer with one thing changed,
// which Transactions must refuse: with want, a verifier.Error reason, or
// wantErr, a sentinel error.
type responseVector struct {
	id, clause string
	want       verifier.Reason
	wantErr    error
	// answer builds the answer to begun; it may also change f.
	answer func(t *testing.T, f *txFixture, begun verifier.Begun) string
}

func otherP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var responseNegativeVectors = []responseVector{
	{
		id: "response-encrypted-to-another-key", clause: "OpenID4VP 1.0 §8.3 (response encryption)", want: verifier.ReasonMalformed,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			return f.answer(begun, func(r *wallet.AuthorizationRequest) { r.ResponseEncryptionKey = &otherP256(t).PublicKey })
		},
	},
	{
		id: "response-ciphertext-tampered", clause: "RFC 7516 §5.2 (authentication tag)", want: verifier.ReasonMalformed,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			parts := strings.Split(f.answer(begun, nil), ".")
			c := []byte(parts[3])
			if c[0] == 'A' {
				c[0] = 'B'
			} else {
				c[0] = 'A'
			}
			parts[3] = string(c)
			return strings.Join(parts, ".")
		},
	},
	{
		id: "response-not-a-jwe", clause: "OpenID4VP 1.0 §8.3.1 (direct_post.jwt)", want: verifier.ReasonMalformed,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			parts := strings.Split(f.answer(begun, nil), ".")
			return parts[0] + "." + parts[1] + "." + parts[2] // a JWS-shaped string with the JWE's header
		},
	},
	{
		id: "response-unknown-kid", clause: "OpenID4VP 1.0 §8.3 (the request's response key)", wantErr: verifier.ErrTransactionUnknown,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			return f.answer(begun, func(r *wallet.AuthorizationRequest) { r.ResponseEncryptionKeyID = "no-such-key" })
		},
	},
	{
		id: "response-state-mismatch", clause: "OpenID4VP 1.0 §5.3, RFC 6749 §4.1.2 (state)", want: verifier.ReasonStateMismatch,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			return f.answer(begun, func(r *wallet.AuthorizationRequest) { r.State = "another-state" })
		},
	},
	{
		id: "response-another-nonce", clause: "OpenID4VP 1.0 §14.1 (nonce)", want: verifier.ReasonHolderBinding,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			return f.answer(begun, func(r *wallet.AuthorizationRequest) { r.Nonce = "another-nonce" })
		},
	},
	{
		id: "response-another-audience", clause: "OpenID4VP 1.0 Appendix B.3.6 (Key Binding JWT aud)", want: verifier.ReasonHolderBinding,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			return f.answer(begun, func(r *wallet.AuthorizationRequest) { r.ClientID = "x509_hash:another-verifier" })
		},
	},
	{
		id: "response-replayed", clause: "OpenID4VP 1.0 §14.1 (one answer per request)", wantErr: verifier.ErrTransactionAnswered,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			jwe := f.answer(begun, nil)
			if _, err := f.txs.HandleResponse(context.Background(), jwe); err != nil {
				t.Fatalf("the first answer: %v", err)
			}
			return jwe
		},
	},
	{
		id: "response-after-the-request-expired", clause: "OpenID4VP 1.0 §14.1 (fresh nonce)", wantErr: verifier.ErrTransactionExpired,
		answer: func(t *testing.T, f *txFixture, begun verifier.Begun) string {
			jwe := f.answer(begun, nil)
			f.now = f.now.Add(time.Hour)
			return jwe
		},
	},
}

// Every response-layer negative vector is refused, for its reason; the
// unchanged answer, the control, is accepted.
func TestResponseNegativeVectors(t *testing.T) {
	control := newTxFixture(t, nil)
	if _, err := control.txs.HandleResponse(context.Background(), control.answer(control.begin("browser-binding-A", false), nil)); err != nil {
		t.Fatalf("the control is refused, so no refusal below means anything: %v", err)
	}
	for _, vec := range responseNegativeVectors {
		t.Run(vec.id, func(t *testing.T) {
			f := newTxFixture(t, nil)
			begun := f.begin("browser-binding-A", false)
			_, err := f.txs.HandleResponse(context.Background(), vec.answer(t, f, begun))
			var verr *verifier.Error
			switch {
			case err == nil:
				t.Fatalf("accepted (%s)", vec.clause)
			case vec.wantErr != nil && !errors.Is(err, vec.wantErr):
				t.Errorf("refused for another reason: %v, want %v (%s)", err, vec.wantErr, vec.clause)
			case vec.wantErr == nil && (!errors.As(err, &verr) || verr.Reason() != vec.want):
				t.Errorf("refused for another reason: %v, want reason %q (%s)", err, vec.want, vec.clause)
			}
		})
	}
}
