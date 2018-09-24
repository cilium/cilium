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
	"context"
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"

	"github.com/spf13/viper"
)

// the global Envoy instance
var envoyProxy *envoy.Envoy

// envoyRedirect implements the Redirect interface for an l7 proxy.
type envoyRedirect struct {
	listenerName string
	xdsServer    *envoy.XDSServer
}

var envoyOnce sync.Once

// createEnvoyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createEnvoyRedirect(r *Redirect, stateDir string, xdsServer *envoy.XDSServer, wg *completion.WaitGroup, acked func(redirectPort uint16), realloc func() (uint16, error)) (RedirectImplementation, error) {
	envoyOnce.Do(func() {
		// Start Envoy on first invocation
		envoyProxy = envoy.StartEnvoy(stateDir, viper.GetString("envoy-log"), 0)
	})

	if envoyProxy != nil {
		redir := &envoyRedirect{
			listenerName: fmt.Sprintf("%s:%d", r.id, r.ProxyPort),
			xdsServer:    xdsServer,
		}

		ip := r.localEndpoint.GetIPv4Address()
		if ip == "" {
			ip = r.localEndpoint.GetIPv6Address()
		}
		if ip == "" {
			return nil, fmt.Errorf("%s: Cannot create redirect, proxy local endpoint has no IP address", r.id)
		}

		retries := 0
		maxRetries := 10
		var comp *completion.Completion
		comp = wg.AddCompletionWithCallback(func(err error) error {
			r.mutex.Lock()
			oldPort := r.ProxyPort
			r.mutex.Unlock()

			switch err {
			case nil:
				acked(oldPort)
			case context.Canceled, context.DeadlineExceeded:
				// nothing
			default:
				port, err2 := realloc()
				if err2 != nil {
					return err2
				}

				retries++

				// AddListener cannot be called from the callback due to a locks being held.
				go func() {
					// RemoveListener
					xdsServer.RemoveListener(redir.listenerName, nil) // Not using comp, it will time out.

					// Create a new one with the reallocated port
					if retries < maxRetries {
						log.Debugf("Retrying redirect %s with reallocated proxyport (%d -> %d)", r.id, oldPort, port)
						redir.listenerName = fmt.Sprintf("%s:%d", r.id, port)
						xdsServer.AddListener(redir.listenerName, r.parserType, ip, port, r.ingress, comp)
					}
				}()

				if retries >= maxRetries {
					log.Errorf("Envoy: Failed to apply new listener configuration after %d retries (irrecoverable NACK received), removing listener %s", retries, redir.listenerName)
					return err
				}
			}
			return nil
		})

		// redirect not visible yet, no need to lock for ProxyPort
		xdsServer.AddListener(redir.listenerName, r.parserType, ip, r.ProxyPort, r.ingress, comp)

		return redir, nil
	}

	return nil, fmt.Errorf("%s: Envoy proxy process failed to start, cannot add redirect", r.id)
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (r *envoyRedirect) UpdateRules(wg *completion.WaitGroup) error {
	return nil
}

// Close the redirect.
func (r *envoyRedirect) Close(wg *completion.WaitGroup) {
	if envoyProxy != nil {
		r.xdsServer.RemoveListener(r.listenerName, wg.AddCompletion())
	}
}
