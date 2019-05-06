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
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricLabelReason = "reason"
)

// Parameters are the user specified parameters
type Parameters struct {
	// MinInterval is the minimum required interval between invocations of
	// TriggerFunc
	MinInterval time.Duration

	// TriggerFunc is the function to be called when Trigger() is called
	// while respecting MinInterval and serialization
	TriggerFunc func(reasons []string)

	// PrometheusMetrics enables use of a prometheus metric. Name must be set
	PrometheusMetrics bool

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
	wakeupChan chan bool

	// closeChan is used to stop the background trigger routine
	closeChan chan struct{}

	triggerReasons metrics.CounterVec
	triggerFolds   prometheus.Gauge
	callDurations  prometheus.ObserverVec

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

	if p.PrometheusMetrics && p.Name == "" {
		return nil, fmt.Errorf("trigger name must be provided when enabling metrics")
	}

	t := &Trigger{
		params:        p,
		wakeupChan:    make(chan bool, 1),
		closeChan:     make(chan struct{}, 1),
		foldedReasons: newReasonStack(),
	}

	// Guarantee that initial trigger has no delay
	if p.MinInterval > time.Duration(0) {
		t.lastTrigger = time.Now().Add(-1 * p.MinInterval)
	}

	if p.PrometheusMetrics {
		t.triggerReasons = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "triggers",
			Name:      p.Name + "_total",
			Help:      "Total number of trigger invocations labelled by reason",
		}, []string{metricLabelReason})

		if err := metrics.Register(t.triggerReasons); err != nil {
			return nil, fmt.Errorf("unable to register prometheus collector: %s", err)
		}

		t.triggerFolds = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "triggers",
			Name:      p.Name + "_folds",
			Help:      "Current level of trigger folds",
		})

		if err := metrics.Register(t.triggerFolds); err != nil {
			metrics.Unregister(t.triggerReasons)
			return nil, fmt.Errorf("unable to register prometheus collector: %s", err)
		}

		t.callDurations = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "triggers",
			Name:      p.Name + "_call_duration_seconds",
			Help:      "Length of duration trigger used to execute",
		}, []string{"type"})

		if err := metrics.Register(t.callDurations); err != nil {
			metrics.Unregister(t.triggerReasons)
			metrics.Unregister(t.triggerFolds)
			return nil, err
		}
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

	if t.params.PrometheusMetrics {
		t.triggerReasons.WithLabelValues(reason).Inc()
	}

	select {
	case t.wakeupChan <- true:
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
	if t.params.PrometheusMetrics {
		metrics.Unregister(t.triggerReasons)
		metrics.Unregister(t.triggerFolds)
		metrics.Unregister(t.callDurations)
	}
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

			if t.params.PrometheusMetrics {
				callDuration := time.Since(beforeTrigger)
				t.callDurations.WithLabelValues("duration").Observe(callDuration.Seconds())
				t.callDurations.WithLabelValues("latency").Observe(callLatency.Seconds())
				t.triggerFolds.Set(float64(numFolds))
			}
		}

		select {
		case <-t.wakeupChan:
		case <-time.After(t.params.sleepInterval):

		case <-t.closeChan:
			return
		}
	}
}
