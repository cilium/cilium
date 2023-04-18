// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// the global EnvoyAdminClient instance
var envoyAdminClient *envoy.EnvoyAdminClient

// requiredEnvoyVersionSHA is set during build
// Running Envoy version will be checked against `requiredEnvoyVersionSHA`.
// By default, cilium-agent will fail to start if there is a version mismatch.
var requiredEnvoyVersionSHA string

// envoyRedirect implements the RedirectImplementation interface for an l7 proxy.
type envoyRedirect struct {
	listenerName string
	xdsServer    *envoy.XDSServer
}

var envoyOnce sync.Once

func initEnvoy(runDir, proxySocketDir string, xdsServer *envoy.XDSServer, wg *completion.WaitGroup) {
	envoyOnce.Do(func() {
		if option.Config.EmbeddedProxyEnabled {
			// Start embedded Envoy on first invocation
			embeddedEnvoy := envoy.StartEmbeddedEnvoy(runDir, proxySocketDir, option.Config.EnvoyLogPath, 0)
			if embeddedEnvoy != nil {
				envoyAdminClient = embeddedEnvoy.GetAdminClient()
			}

			// Add Prometheus listener if the port is (properly) configured
			if option.Config.ProxyPrometheusPort < 0 || option.Config.ProxyPrometheusPort > 65535 {
				log.WithField(logfields.Port, option.Config.ProxyPrometheusPort).Error("Envoy: Invalid configured proxy-prometheus-port")
			} else if option.Config.ProxyPrometheusPort != 0 {
				xdsServer.AddMetricsListener(uint16(option.Config.ProxyPrometheusPort), wg)
			}
		} else {
			envoyAdminClient = envoy.NewEnvoyAdminClientForSocket(proxySocketDir)
		}

		if envoyAdminClient != nil && !option.Config.DisableEnvoyVersionCheck {
			envoyVersion, err := envoyAdminClient.GetEnvoyVersion()
			if err != nil {
				log.WithError(err).Error("Envoy: Unable to retrieve Envoy version")
				return
			}

			log.Infof("Envoy: Version %s", envoyVersion)

			// Make sure Envoy version matches ours
			if !strings.HasPrefix(envoyVersion, requiredEnvoyVersionSHA) {
				log.Errorf("Envoy: Envoy version %s does not match with required version %s, aborting.",
					envoyVersion, requiredEnvoyVersionSHA)
			}
		}
	})
}

// createEnvoyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createEnvoyRedirect(r *Redirect, runDir, proxySocketDir string, xdsServer *envoy.XDSServer, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) (RedirectImplementation, error) {
	initEnvoy(runDir, proxySocketDir, xdsServer, wg)

	l := r.listener
	if envoyAdminClient != nil {
		redirect := &envoyRedirect{
			listenerName: net.JoinHostPort(r.name, fmt.Sprintf("%d", l.proxyPort)),
			xdsServer:    xdsServer,
		}
		// Only use original source address for egress
		if l.ingress {
			mayUseOriginalSourceAddr = false
		}
		xdsServer.AddListener(redirect.listenerName, policy.L7ParserType(l.proxyType), l.proxyPort, l.ingress,
			mayUseOriginalSourceAddr, wg)

		return redirect, nil
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
	if envoyAdminClient == nil {
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
