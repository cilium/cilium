// Copyright 2019-2020 Authors of Cilium
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

package metrics

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
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
