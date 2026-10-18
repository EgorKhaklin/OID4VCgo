package statuslist

import (
	"math"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A Status List Token needs an iat that isn't in the future, and with
// MaxAge, isn't older than that; its exp must be in range. Without
// these, an old list signed before a revocation could be replayed.
func TestVerifyToken_Freshness(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Signed without IssueToken's checks, which refuse some of these.
	issue := func(iat int64, exp *int64) string {
		t.Helper()
		token, err := signToken(key, jose.ES256, TokenClaims{Sub: "https://example.com/statuslists/1", Iat: iat, Exp: exp, StatusList: sl}, map[string]any{"typ": TokenTyp})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	outOfRange := int64(math.MaxInt64 - 10)
	inAnHour := now.Add(time.Hour).Unix()
	for name, tc := range map[string]struct {
		token string
		opts  VerifyOptions
	}{
		"no iat":               {issue(0, nil), VerifyOptions{}},
		"iat in the future":    {issue(now.Add(time.Hour).Unix(), nil), VerifyOptions{}},
		"iat out of range":     {issue(outOfRange, nil), VerifyOptions{}},
		"older than MaxAge":    {issue(now.Add(-2*time.Hour).Unix(), nil), VerifyOptions{MaxAge: time.Hour}},
		"exp out of range":     {issue(now.Unix(), &outOfRange), VerifyOptions{}},
		"beyond a stated skew": {issue(now.Add(10*time.Second).Unix(), nil), VerifyOptions{MaxClockSkew: time.Second}},
		// Neither exp nor MaxAge bounds it: DefaultMaxAgeWithoutExp does.
		"old, no exp, no MaxAge": {issue(now.Add(-48*time.Hour).Unix(), nil), VerifyOptions{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyToken(tc.token, &key.PublicKey, jose.ES256, tc.opts); err == nil {
				t.Error("accepted")
			}
		})
	}
	for name, tc := range map[string]struct {
		token string
		opts  VerifyOptions
	}{
		"fresh":                  {issue(now.Unix(), nil), VerifyOptions{}},
		"a little ahead":         {issue(now.Add(30*time.Second).Unix(), nil), VerifyOptions{}},
		"old, with a future exp": {issue(now.Add(-48*time.Hour).Unix(), &inAnHour), VerifyOptions{}},
		"within MaxAge":          {issue(now.Add(-30*time.Minute).Unix(), nil), VerifyOptions{MaxAge: time.Hour}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyToken(tc.token, &key.PublicKey, jose.ES256, tc.opts); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}
