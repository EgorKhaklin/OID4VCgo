package statuslist

import "testing"

// A Fetcher is hardened for production only with none of its address
// policy relaxations set.
func TestFetcher_HardenedForProduction(t *testing.T) {
	for name, tc := range map[string]struct {
		f  Fetcher
		ok bool
	}{
		"default":            {Fetcher{MaxBytes: 1 << 10}, true},
		"AllowLoopback":      {Fetcher{AllowLoopback: true}, false},
		"AllowPrivate":       {Fetcher{AllowPrivate: true}, false},
		"AllowProxy":         {Fetcher{AllowProxy: true}, false},
		"UncheckedTransport": {Fetcher{UncheckedTransport: true}, false},
	} {
		if got := tc.f.HardenedForProduction(); got != tc.ok {
			t.Errorf("%s: HardenedForProduction = %v, want %v", name, got, tc.ok)
		}
	}
}
