// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package trigger

import (
	"fmt"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// MetricsObserver is the interface a metrics collector has to implement in
// order to collect trigger metrics
type MetricsObserver interface {
	// PostRun is called after a trigger run with the call duration, the
	// latency between 1st queue request and the call run and the number of
	// queued events folded into the last run
	PostRun(callDuration, latency time.Duration, folds int)

	// QueueEvent is called when Trigger() is called to schedule a trigger
	// run
	QueueEvent(reason string)
}

// Parameters are the user specified parameters
type Parameters struct {
	// MinInterval is the minimum required interval between invocations of
	// TriggerFunc
	MinInterval time.Duration

	// TriggerFunc is the function to be called when Trigger() is called
	// while respecting MinInterval and serialization
	TriggerFunc func(reasons []string)

	// ShutdownFunc is called when the trigger is shut down
	ShutdownFunc func()

	MetricsObserver MetricsObserver

	// Name is the unique name of the trigger. It must be provided in a
	// format compatible to be used as prometheus name string.
	Name string

	// sleepInterval controls the waiter sleep duration. This parameter is
	// only exposed to tests
	sleepInterval time.Duration
}

type reasonStack map[string]struct{}

func newReasonStack() reasonStack {
	return map[string]struct{}{}
}

func (r reasonStack) add(reason string) {
	r[reason] = struct{}{}
}

func (r reasonStack) slice() []string {
	result := make([]string, len(r))
	i := 0
	for reason := range r {
		result[i] = reason
		i++
	}
	return result
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
	wakeupChan chan struct{}

	// closeChan is used to stop the background trigger routine
	closeChan chan struct{}

	// numFolds is the current count of folds that happened into the
	// currently scheduled trigger
	numFolds int

	// foldedReasons is the sum of all unique reasons folded together.
	foldedReasons reasonStack

	waitStart time.Time
}

// NewTrigger returns a new trigger based on the provided parameters
func NewTrigger(p Parameters) (*Trigger, error) {
	if p.sleepInterval == 0 {
		p.sleepInterval = time.Second
	}

	if p.TriggerFunc == nil {
		return nil, fmt.Errorf("trigger function is nil")
	}

	t := &Trigger{
		params:        p,
		wakeupChan:    make(chan struct{}, 1),
		closeChan:     make(chan struct{}, 1),
		foldedReasons: newReasonStack(),
	}

	// Guarantee that initial trigger has no delay
	if p.MinInterval > time.Duration(0) {
		t.lastTrigger = time.Now().Add(-1 * p.MinInterval)
	}

	go t.waiter()

	return t, nil
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
func (t *Trigger) TriggerWithReason(reason string) {
	t.mutex.Lock()
	t.trigger = true
	if t.numFolds == 0 {
		t.waitStart = time.Now()
	}
	t.numFolds++
	t.foldedReasons.add(reason)
	t.mutex.Unlock()

	if t.params.MetricsObserver != nil {
		t.params.MetricsObserver.QueueEvent(reason)
	}

	select {
	case t.wakeupChan <- struct{}{}:
	default:
	}
}

// Trigger triggers the call to TriggerFunc as specified in the parameters
// provided to NewTrigger(). It respects MinInterval and ensures that calls to
// TriggerFunc are serialized. This function is non-blocking and will return
// immediately before TriggerFunc is potentially triggered and has completed.
func (t *Trigger) Trigger() {
	t.TriggerWithReason("")
}

// Shutdown stops the trigger mechanism
func (t *Trigger) Shutdown() {
	close(t.closeChan)
}

func (t *Trigger) waiter() {
	sleepTimer, sleepTimerDone := inctimer.New()
	defer sleepTimerDone()
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

			t.mutex.Lock()
			t.lastTrigger = time.Now()
			numFolds := t.numFolds
			t.numFolds = 0
			reasons := t.foldedReasons.slice()
			t.foldedReasons = newReasonStack()
			callLatency := time.Since(t.waitStart)
			t.mutex.Unlock()

			beforeTrigger := time.Now()
			t.params.TriggerFunc(reasons)

			if t.params.MetricsObserver != nil {
				callDuration := time.Since(beforeTrigger)
				t.params.MetricsObserver.PostRun(callDuration, callLatency, numFolds)
			}
		}

		select {
		case <-t.wakeupChan:
		case <-sleepTimer.After(t.params.sleepInterval):

		case <-t.closeChan:
			shutdownFunc := t.params.ShutdownFunc
			if shutdownFunc != nil {
				shutdownFunc()
			}
			return
		}
	}
}
