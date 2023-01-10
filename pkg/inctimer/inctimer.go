// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package inctimer

import "time"

// IncTimer should be the preferred mechanism over
// calling `time.After` when wanting an `After`-like
// function in a loop. This prevents memory build up
// as the `time.After` method creates a new timer
// instance every time it is called, and it is not
// garbage collected until after it fires. Conversely,
// IncTimer only uses one timer and correctly stops
// the timer, clears its channel, and resets it
// everytime that `After` is called.
type IncTimer interface {
	After(time.Duration) <-chan time.Time
}

type incTimer struct {
	t *time.Timer
}

// New creates a new IncTimer and a done function.
// IncTimer only uses one timer and correctly stops
// the timer, clears the channel, and resets it every
// time the `After` function is called.
// WARNING: Concurrent use is not expected. The use
// of this timer should be for only one goroutine.
func New() (IncTimer, func() bool) {
	it := &incTimer{}
	return it, it.stop
}

// stop returns true if a scheduled timer has been stopped before execution.
func (it *incTimer) stop() bool {
	if it.t == nil {
		return false
	}
	return it.t.Stop()
}

// After returns a channel that will fire after
// the specified duration.
func (it *incTimer) After(d time.Duration) <-chan time.Time {
	// Stop the previous timer (if any) to garbage collect it.
	// The old timer channel will be garbage collected even if not drained.
	it.stop()

	// We have to create a new timer for each invocation, because it is not
	// possible to safely use https://golang.org/pkg/time/#Timer.Reset if we
	// do not know if the timer channel has already been drained or not (which
	// is the case here, as the client might have drained the channel already).
	// Even after stopping a timer, it's not safe to attempt to drain its
	// timer channel with a default case (for the case where the client has
	// drained the channel already), as there is a small window where a timer
	// is considered expired, but the channel has not received a value yet [1].
	// This would cause us to erroneously take the default case (assuming the
	// channel has been drained by the client), when in fact the channel just
	// has not received a value yet. Because the two cases (client has drained
	// vs. value not received yet) are indistinguishable for us, we cannot use
	// Timer.Reset and need to create a new timer.
	//
	// [1] The reason why this small window occurs, is because the Go runtime
	// will remove a timer from the heap and and mark it as deleted _before_
	// it actually executes the timer function f:
	// https://github.com/golang/go/blob/go1.16/src/runtime/time.go#L876
	// This causes t.Stop to report the timer as already expired while it is
	// in fact currently running:
	// https://github.com/golang/go/blob/go1.16/src/runtime/time.go#L352
	it.t = time.NewTimer(d)
	return it.t.C
}

// After wraps the time.After function to get
// around the customvet warning for cases
// where it is inconvenient to use the instantiated
// version.
func After(d time.Duration) <-chan time.Time {
	return time.After(d)
}
