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
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// the global Envoy instance
var envoyProxy *envoy.Envoy

// envoyRedirect implements the RedirectImplementation interface for an l7 proxy.
type envoyRedirect struct{}

var envoyOnce sync.Once

func (p *Proxy) StartEnvoy() {
	if envoyProxy == nil {
		envoyOnce.Do(func() {
			// Start Envoy on first invocation
			envoyProxy = envoy.StartEnvoy(option.Config.RunDir, option.Config.EnvoyLogPath, 0)
		})
	}
}

// createEnvoyListener configures an Envoy listener
// Once created we keep the listeners running until Cilium agent terminates.
func createEnvoyListener(p *Proxy, pp *ProxyPort, wg *completion.WaitGroup) (error, revert.RevertFunc) {
	if envoyProxy != nil {
		listenerName := fmt.Sprintf("%s:%d", pp.name, pp.proxyPort)

		// Only use original source address for egress
		mayUseOriginalSourceAddr := false
		if !pp.ingress {
			mayUseOriginalSourceAddr = p.datapathUpdater.SupportsOriginalSourceAddr()
		}
		p.XDSServer.AddListener(listenerName, pp.parserType, pp.proxyPort, pp.ingress,
			mayUseOriginalSourceAddr, wg)

		return nil, func() error {
			// RevertFunc is called when a NACK is received from Envoy, which may be
			// due to faulty listener configuration, e.g., due to the proxy port
			// already being in use. So we must remove the potentially faulty listener
			// here.
			//
			// Timeout not needed as we cancel the context immediately below.
			completionCtx, cancel := context.WithCancel(context.Background())
			proxyWaitGroup := completion.NewWaitGroup(completionCtx)
			p.XDSServer.RemoveListener(listenerName, proxyWaitGroup)
			// Don't wait for an ACK. This is best-effort. Just clean up the completions.
			cancel()
			proxyWaitGroup.Wait() // Ignore the returned error.
			return nil
		}
	}
	return fmt.Errorf("Envoy proxy process not started, cannot create listener"), nil
}

// createEnvoyRedirect is a no-op.
func (p *Proxy) createEnvoyRedirect(r *Redirect) (RedirectImplementation, error) {
	if envoyProxy != nil {
		return &envoyRedirect{}, nil
	}

	return nil, fmt.Errorf("%s: Envoy proxy process not started, cannot add redirect",
		r.listener.name)
}

// UpdateRules is a no-op for envoy, as redirect data is synchronized via the
// xDS cache.
func (k *envoyRedirect) UpdateRules(wg *completion.WaitGroup, l4 *policy.L4Filter) (revert.RevertFunc, error) {
	return func() error { return nil }, nil
}

// Close is a no-op for Envoy, as the shared listener is managed separately
func (r *envoyRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil
}
