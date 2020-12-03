// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	t := time.NewTimer(time.Nanosecond)
	return &incTimer{
		t: t,
	}, t.Stop
}

// After returns a channel that will fire after
// the specified duration.
func (it *incTimer) After(d time.Duration) <-chan time.Time {
	// We cannot call reset on an expired timer,
	// so we need to stop it and drain it first.
	// See https://golang.org/pkg/time/#Timer.Reset for more details.
	if !it.t.Stop() {
		// It could be that the channel was read already
		select {
		case <-it.t.C:
		default:
		}
	}
	it.t.Reset(d)
	return it.t.C
}

// After wraps the time.After function to get
// around the customvet warning for cases
// where it is inconvenient to use the instantiated
// version.
func After(d time.Duration) <-chan time.Time {
	return time.After(d)
}
