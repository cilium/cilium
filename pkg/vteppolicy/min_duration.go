// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"github.com/cilium/cilium/pkg/time"
)

// MinDuration represents a structure to manage timing intervals with a minimum duration and a time channel.
// It is not thread-safe, so it must be used only within a single goroutine.
type MinDuration struct {
	c           <-chan time.Time
	minInterval time.Duration
	lastCheck   time.Time
}

// NewMinDuration returns a new MinDuration instance if the given minInterval is positive.
func NewMinDuration(minInterval time.Duration) *MinDuration {
	if minInterval <= 0 {
		return nil
	}

	if minInterval > 30*time.Second {
		// It could be parametrized, but for now keep it simple.
		minInterval = 30 * time.Second
	}

	return &MinDuration{
		// Set it to -minInterval, so the first run should occur immediately.
		// It could be parametrized, but for now keep it simple.
		lastCheck:   time.Now().Add(-minInterval),
		minInterval: minInterval,
	}
}

// GetChannel returns the channel that fires when the required duration has passed since the last reconciliation,
// or nil if it is disabled.
// Nil channel can be used in select case statements, and it will not be fire
func (m *MinDuration) GetChannel() <-chan time.Time {
	if m != nil {
		return m.c
	}

	return nil
}

// Check returns true if:
// - this feature is disabled.
// - or the required duration has passed since the given last time.
func (m *MinDuration) Check() bool {
	if m == nil {
		return true
	}

	t := time.Since(m.lastCheck)
	if t < m.minInterval {
		if m.c == nil {
			m.c = time.After(m.minInterval - t)
		}
	} else {
		// If time.After was created beforehand, then it is released now by the time.After function.
		m.c = nil
	}

	return m.c == nil
}

// SetLastCheck sets the last check time to now.
// It should be called when an action is finished.
func (m *MinDuration) SetLastCheck() {
	if m != nil {
		m.lastCheck = time.Now()
	}
}

type retry struct {
	timer *time.Timer
}

func newRetry(d time.Duration) *retry {
	return &retry{
		timer: time.NewTimer(d),
	}
}

func (r *retry) GetChannel() <-chan time.Time {
	if r == nil || r.timer == nil {
		return nil
	}

	return r.timer.C
}

func (r *retry) Stop() {
	if r == nil || r.timer == nil {
		return
	}

	if !r.timer.Stop() {
		// Drain channel if timer already fired
		select {
		case <-r.timer.C:
		default:
		}
	}

	r.timer = nil
}
