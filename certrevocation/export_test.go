package certrevocation

import (
	"context"
	"time"
)

// SetScheduleForTest replaces the sleep and jitter Run uses, so a test
// can run its loop without waiting.
func (r *Refresher) SetScheduleForTest(wait func(context.Context, time.Duration) bool, jitter func(time.Duration) time.Duration) {
	r.wait, r.jitter = wait, jitter
}
