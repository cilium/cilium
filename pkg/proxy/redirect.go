// Copyright 2016-2018 Authors of Cilium
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

package proxy

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
)

// RedirectImplementation is the generic proxy redirect interface that each
// proxy redirect type must implement
type RedirectImplementation interface {
	// UpdateRules notifies the proxy implementation that the new
	// rules in parameter 'rules' are to be applied.  Initially
	// called right after the redirect is created. The returned
	// revertFunc must revert any changes done here.
	UpdateRules(rules policy.L7DataMap) revert.RevertFunc

	// Close closes and cleans up resources associated with the
	// redirect implementation.
	Close()
}

type Redirect struct {
	// The following fields are only written to during initialization, it
	// is safe to read these fields without locking the mutex
	listener       *ProxyPort
	dstPort        uint16
	endpointID     uint64
	localEndpoint  logger.EndpointUpdater
	created        time.Time
	implementation RedirectImplementation

	// The following fields are updated while the redirect is alive, the
	// mutex must be held to read and write these fields
	mutex       lock.RWMutex
	lastUpdated time.Time
}

func newRedirect(localEndpoint logger.EndpointUpdater, listener *ProxyPort, dstPort uint16) *Redirect {
	now := time.Now()
	return &Redirect{
		listener:      listener,
		dstPort:       dstPort,
		endpointID:    localEndpoint.GetID(),
		localEndpoint: localEndpoint,
		created:       now,
		lastUpdated:   now,
	}
}
