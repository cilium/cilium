// Copyright 2018 Authors of Cilium
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

package trigger

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

// Parameters are the user specified parameters
type Parameters struct {
	// MinInterval is the minimum required interval between invocations of
	// TriggerFunc
	MinInterval time.Duration

	// TriggerFunc is the function to be called when Trigger() is called
	// while respecting MinInterval and serialization
	TriggerFunc func()

	// sleepInterval controls the waiter sleep duration. This parameter is
	// only exposed to tests
	sleepInterval time.Duration
}

// Trigger represents an active trigger logic. Use NewTrigger() to create a
// trigger
type Trigger struct {
	// protect mutual access of 'trigger' between Trigger() and waiter()
	mutex   lock.Mutex
	trigger bool

	// params are the user specified parameters
	params Parameters

	// lastTrigger is the timestamp of the last invoked trigger
	lastTrigger time.Time

	// wakeupCan is used to wake up the background trigger routine
	wakeupChan chan bool

	// closeChan is used to stop the background trigger routine
	closeChan chan struct{}
}

// NewTrigger returns a new trigger based on the provided parameters
func NewTrigger(p Parameters) *Trigger {
	if p.sleepInterval == 0 {
		p.sleepInterval = time.Second
	}

	t := &Trigger{
		params:     p,
		wakeupChan: make(chan bool, 1),
		closeChan:  make(chan struct{}, 1),
	}

	go t.waiter()

	return t
}

// needsDelay returns whether and how long of a delay is required to fullfil
// MinInterval
func (t *Trigger) needsDelay() (bool, time.Duration) {
	if t.params.MinInterval == time.Duration(0) {
		return false, 0
	}

	sleepTime := time.Since(t.lastTrigger.Add(t.params.MinInterval))
	return sleepTime < 0, sleepTime * -1
}

// Trigger triggers the call to TriggerFunc as specified in the parameters
// provided to NewTrigger(). It respects MinInterval and ensures that calls to
// TriggerFunc are serialized. This function is non-blocking and will return
// immediately before TriggerFunc is potentially triggered and has completed.
func (t *Trigger) Trigger() {
	t.mutex.Lock()
	t.trigger = true
	t.mutex.Unlock()

	select {
	case t.wakeupChan <- true:
	default:
	}
}

// Shutdown stops the trigger mechanism
func (t *Trigger) Shutdown() {
	close(t.closeChan)
}

func (t *Trigger) waiter() {
	for {
		// keep critical section as small as possible
		t.mutex.Lock()
		triggerEnabled := t.trigger
		t.trigger = false
		t.mutex.Unlock()

		// run the trigger function
		if triggerEnabled {
			if delayNeeded, delay := t.needsDelay(); delayNeeded {
				time.Sleep(delay)
			}

			if t.params.TriggerFunc != nil {
				t.params.TriggerFunc()
			}
			t.lastTrigger = time.Now()
		}

		select {
		case <-t.wakeupChan:
		case <-time.After(t.params.sleepInterval):

		case <-t.closeChan:
			return
		}
	}
}
