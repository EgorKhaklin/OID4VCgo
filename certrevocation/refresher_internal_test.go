package certrevocation

import (
	"testing"
	"time"
)

func TestRefreshDelay(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	held := func(fetched, next time.Duration) scheduleEntry {
		return scheduleEntry{held: true, fetchedAt: now.Add(fetched), nextUpdate: now.Add(next)}
	}
	tests := map[string]struct {
		entries []scheduleEntry
		want    time.Duration
	}{
		"nothing held: at once, floored":   {[]scheduleEntry{{}}, minRefreshInterval},
		"far nextUpdate: capped":           {[]scheduleEntry{held(0, 10*time.Hour)}, time.Hour},
		"halfway to nextUpdate":            {[]scheduleEntry{held(0, 20*time.Minute)}, 10 * time.Minute},
		"halfway from an earlier fetch":    {[]scheduleEntry{held(-40*time.Minute, 60*time.Minute)}, 10 * time.Minute},
		"earliest of several":              {[]scheduleEntry{held(0, 50*time.Minute), held(0, 30*time.Minute)}, 15 * time.Minute},
		"one unfetched among held":         {[]scheduleEntry{held(0, 50*time.Minute), {}}, minRefreshInterval},
		"halfway passed: floored":          {[]scheduleEntry{held(-2*time.Hour, 30*time.Minute)}, minRefreshInterval},
		"nextUpdate passed: floored":       {[]scheduleEntry{held(-2*time.Hour, -time.Hour)}, minRefreshInterval},
		"close to nextUpdate: still a min": {[]scheduleEntry{held(0, 90*time.Second)}, minRefreshInterval},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := refreshDelay(now, tc.entries, time.Hour); got != tc.want {
				t.Errorf("refreshDelay = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRetryDelay(t *testing.T) {
	none := func(time.Duration) time.Duration { return 0 }
	most := func(n time.Duration) time.Duration { return n - 1 }
	tests := []struct {
		failures       int
		lowest, utmost time.Duration
	}{
		{1, 15 * time.Second, 30*time.Second - 1},
		{2, 30 * time.Second, time.Minute - 1},
		{3, time.Minute, 2*time.Minute - 1},
		{7, 15 * time.Minute, 30*time.Minute - 1}, // 32 minutes, capped
		{1000, 15 * time.Minute, 30*time.Minute - 1},
	}
	for _, tc := range tests {
		if got := retryDelay(tc.failures, none); got != tc.lowest {
			t.Errorf("retryDelay(%d), no jitter = %v, want %v", tc.failures, got, tc.lowest)
		}
		if got := retryDelay(tc.failures, most); got != tc.utmost {
			t.Errorf("retryDelay(%d), most jitter = %v, want %v", tc.failures, got, tc.utmost)
		}
	}
}
