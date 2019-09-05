// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import (
	"time"

	"github.com/cilium/cilium/pkg/identity"
)

// WaitForIdentity waits for up to timeoutDuration amount of time for the
// endpoint to have an identity. If the timeout is reached, returns nil.
func (e *Endpoint) WaitForIdentity(timeoutDuration time.Duration) *identity.Identity {
	timeout := time.NewTimer(timeoutDuration)
	defer timeout.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	var secID *identity.Identity
	for {
		select {
		case <-timeout.C:
			return nil
		case <-tick.C:
			e.unconditionalRLock()
			secID = e.SecurityIdentity
			e.runlock()
			if secID != nil {
				return secID
			}
		}
	}
}
