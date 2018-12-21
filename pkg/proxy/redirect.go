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
	"fmt"
	"github.com/cilium/cilium/pkg/revert"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

// RedirectImplementation is the generic proxy redirect interface that each
// proxy redirect type must implement
type RedirectImplementation interface {
	// UpdateRules notifies the proxy implementation that the new rules in
	// parameter l4 are to be applied. The implementation should .Add to the
	// WaitGroup if the update is asynchronous and the update should not return
	// until it is complete.
	// The returned RevertFunc must be non-nil.
	// Note: UpdateRules is not called when a redirect is created.
	UpdateRules(wg *completion.WaitGroup, l4 *policy.L4Filter) (revert.RevertFunc, error)

	// Close closes and cleans up resources associated with the redirect
	// implementation. The implementation should .Add to the WaitGroup if the
	// update is asynchronous and the update should not return until it is
	// complete.
	Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc)
}

type Redirect struct {
	// The following fields are only written to during initialization, it
	// is safe to read these fields without locking the mutex

	// ProxyPort is the port the redirects redirects to where the proxy is
	// listening on
	ProxyPort      uint16
	endpointID     uint64
	listenerName   string
	ingress        bool
	localEndpoint  logger.EndpointUpdater
	parserType     policy.L7ParserType
	created        time.Time
	implementation RedirectImplementation

	// The following fields are updated while the redirect is alive, the
	// mutex must be held to read and write these fields
	mutex       lock.RWMutex
	lastUpdated time.Time
	rules       policy.L7DataMap
}

func newRedirect(localEndpoint logger.EndpointUpdater, listenerName string) *Redirect {
	return &Redirect{
		localEndpoint: localEndpoint,
		listenerName:  listenerName,
		created:       time.Now(),
		lastUpdated:   time.Now(),
	}
}

// updateRules updates the rules of the redirect, Redirect.mutex must be held
func (r *Redirect) updateRules(l4 *policy.L4Filter) revert.RevertFunc {
	oldRules := r.rules
	r.rules = make(policy.L7DataMap, len(l4.L7RulesPerEp))
	for key, val := range l4.L7RulesPerEp {
		r.rules[key] = val
	}
	return func() error {
		r.mutex.Lock()
		r.rules = oldRules
		r.mutex.Unlock()
		return nil
	}
}

// removeProxyMapEntryOnClose is called after the proxy has closed a connection
// and will remove the proxymap entry for that connection
func (r *Redirect) removeProxyMapEntryOnClose(c net.Conn) error {
	key, err := getProxyMapKey(c, r.ProxyPort)
	if err != nil {
		return fmt.Errorf("unable to extract proxymap key: %s", err)
	}

	return proxymap.Delete(key)
}
