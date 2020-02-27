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
