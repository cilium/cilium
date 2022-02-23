// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// the global Envoy instance
var envoyProxy *envoy.Envoy

// envoyRedirect implements the RedirectImplementation interface for an l7 proxy.
type envoyRedirect struct {
	listenerName string
	xdsServer    *envoy.XDSServer
}

var envoyOnce sync.Once

func startEnvoy(stateDir string, xdsServer *envoy.XDSServer, wg *completion.WaitGroup) {
	envoyOnce.Do(func() {
		// Start Envoy on first invocation
		envoyProxy = envoy.StartEnvoy(stateDir, option.Config.EnvoyLogPath, 0)

		// Add Prometheus listener if the port is (properly) configured
		if option.Config.ProxyPrometheusPort < 0 || option.Config.ProxyPrometheusPort > 65535 {
			log.WithField(logfields.Port, option.Config.ProxyPrometheusPort).Error("Envoy: Invalid configured proxy-prometheus-port")
		} else if option.Config.ProxyPrometheusPort != 0 {
			xdsServer.AddMetricsListener(uint16(option.Config.ProxyPrometheusPort), wg)
		}
	})
}

// createEnvoyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createEnvoyRedirect(r *Redirect, stateDir string, xdsServer *envoy.XDSServer, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) (RedirectImplementation, error) {
	startEnvoy(stateDir, xdsServer, wg)

	l := r.listener
	if envoyProxy != nil {
		redir := &envoyRedirect{
			listenerName: net.JoinHostPort(r.name, fmt.Sprintf("%d", l.proxyPort)),
			xdsServer:    xdsServer,
		}
		// Only use original source address for egress
		if l.ingress {
			mayUseOriginalSourceAddr = false
		}
		xdsServer.AddListener(redir.listenerName, policy.L7ParserType(l.proxyType), l.proxyPort, l.ingress,
			mayUseOriginalSourceAddr, wg)

		return redir, nil
	}

	return nil, fmt.Errorf("%s: Envoy proxy process failed to start, cannot add redirect", r.name)
}

// UpdateRules is a no-op for envoy, as redirect data is synchronized via the
// xDS cache.
func (k *envoyRedirect) UpdateRules(wg *completion.WaitGroup) (revert.RevertFunc, error) {
	return func() error { return nil }, nil
}

// Close the redirect.
func (r *envoyRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	if envoyProxy == nil {
		return nil, nil
	}

	revertFunc := r.xdsServer.RemoveListener(r.listenerName, wg)

	return nil, func() error {
		// Don't wait for an ACK for the reverted xDS updates.
		// This is best-effort.
		revertFunc(completion.NewCompletion(nil, nil))
		return nil
	}
}
