// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

// Operation represents an API operation
type Operation interface{}

// DelaySimulator simulates delays in API calls
type DelaySimulator struct {
	mutex  lock.RWMutex
	delays map[Operation]time.Duration
}

// NewDelaySimulator returns a new DelaySimulator
func NewDelaySimulator() *DelaySimulator {
	return &DelaySimulator{
		delays: map[Operation]time.Duration{},
	}
}

func (d *DelaySimulator) setDelayLocked(op Operation, delay time.Duration) {
	if delay == time.Duration(0) {
		delete(d.delays, op)
	} else {
		d.delays[op] = delay
	}
}

// SetDelay specifies the delay to be simulated for an individual API operation
func (d *DelaySimulator) SetDelay(op Operation, delay time.Duration) {
	d.mutex.Lock()
	d.setDelayLocked(op, delay)
	d.mutex.Unlock()
}

// Delay delays an API operation according to the configuration
func (d *DelaySimulator) Delay(op Operation) {
	d.mutex.RLock()
	delay, ok := d.delays[op]
	d.mutex.RUnlock()
	if ok {
		time.Sleep(delay)
	}
}
