package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A Key Binding JWT's iat far in the future is refused, not taken as
// fresh: its age, negated, used to overflow into a pass.
func TestVerifyKeyBindingJWT_FarFutureIat(t *testing.T) {
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check := KeyBindingCheck{ExpectedAudience: "aud", ExpectedNonce: "n", ExpectedSDHash: "h", MaxAge: 5 * time.Minute}
	verify := func(iat string) error {
		kb, err := jose.Sign(jose.ES256, holderKey, map[string]any{"typ": KeyBindingTyp},
			[]byte(`{"aud":"aud","nonce":"n","sd_hash":"h","iat":`+iat+`}`))
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyKeyBindingJWT(kb, &holderKey.PublicKey, jose.ES256, check)
		return err
	}
	for _, iat := range []string{"1e15", "4102444800", "1e300", "9223372036854775807", "-1"} {
		if err := verify(iat); err == nil {
			t.Errorf("iat %s accepted", iat)
		}
	}
	if err := verify(strconv.FormatInt(time.Now().Unix(), 10)); err != nil {
		t.Errorf("a fresh iat: %v", err)
	}
}

// An issuer's nbf or exp beyond what a time can hold is refused rather
// than wrapping into the past.
func TestCheckIssuerJWTValidityWindow_OutOfRange(t *testing.T) {
	now := time.Now
	for name, claims := range map[string]map[string]any{
		"nbf near int64 max": {"nbf": float64(math.MaxInt64 - 10)},
		"nbf 1e19":           {"nbf": 1e19},
		"exp 1e19":           {"exp": 1e19},
		"exp negative":       {"exp": -1.0},
	} {
		if err := checkIssuerJWTValidityWindow(claims, now, 0); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := checkIssuerJWTValidityWindow(map[string]any{"nbf": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix())}, now, 0); err != nil {
		t.Errorf("a valid window: %v", err)
	}
}
