// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// LastInteraction is the time at which the last apiserver interaction
	// occurred
	LastInteraction eventTimestamper
	// LastSuccessInteraction is the time at which we have received a successful
	// k8s apiserver reply (i.e. a response code 2xx or 4xx).
	LastSuccessInteraction eventTimestamper
)

type eventTimestamper struct {
	timestamp time.Time
	lock      lock.RWMutex
}

// Reset sets the timestamp to the current time
func (e *eventTimestamper) Reset() {
	e.lock.Lock()
	e.timestamp = time.Now()
	e.lock.Unlock()
}

// Time returns the timestamp as set per Reset()
func (e *eventTimestamper) Time() time.Time {
	e.lock.RLock()
	t := e.timestamp
	e.lock.RUnlock()
	return t
}
