// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
