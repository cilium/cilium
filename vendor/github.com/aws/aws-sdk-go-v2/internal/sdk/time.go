package sdk

import (
	"context"
	"time"
)

func init() {
	NowTime = time.Now
	Sleep = time.Sleep
	SleepWithContext = DefaultSleepWithContext
}

// NowTime is a value for getting the current time. This value can be overriden
// for testing mocking out current time.
var NowTime func() time.Time

// Sleep is a value for sleeping for a duration. This value can be overriden
// for testing and mocking out sleep duration.
var Sleep func(time.Duration)

// SleepWithContext will wait for the timer duration to expire, or the context
// is canceled. Which ever happens first. If the context is canceled the Context's
// error will be returned.
//
// This value can be overriden for testing and mocking out sleep duration.
var SleepWithContext func(context.Context, time.Duration) error

// DefaultSleepWithContext will wait for the timer duration to expire, or the context
// is canceled. Which ever happens first. If the context is canceled the Context's
// error will be returned.
func DefaultSleepWithContext(ctx context.Context, dur time.Duration) error {
	t := time.NewTimer(dur)
	defer t.Stop()

	select {
	case <-t.C:
		break
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}
