// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

type onDemandXdsStarter struct {
	XDSServer

	runDir    string
	envoyOnce sync.Once
}

var _ XDSServer = &onDemandXdsStarter{}

func (o *onDemandXdsStarter) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup) {
	if err := o.startEmbeddedEnvoy(nil); err != nil {
		log.WithError(err).Error("Envoy: Failed to start embedded Envoy proxy on demand")
	}

	o.XDSServer.AddListener(name, kind, port, isIngress, mayUseOriginalSourceAddr, wg)
}

func (o *onDemandXdsStarter) UpsertEnvoyResources(ctx context.Context, resources Resources, portAllocator PortAllocator) error {
	if err := o.startEmbeddedEnvoy(nil); err != nil {
		log.WithError(err).Error("Envoy: Failed to start embedded Envoy proxy on demand")
	}

	return o.XDSServer.UpsertEnvoyResources(ctx, resources, portAllocator)
}

func (o *onDemandXdsStarter) UpdateEnvoyResources(ctx context.Context, old, new Resources, portAllocator PortAllocator) error {
	if err := o.startEmbeddedEnvoy(nil); err != nil {
		log.WithError(err).Error("Envoy: Failed to start embedded Envoy proxy on demand")
	}

	return o.XDSServer.UpdateEnvoyResources(ctx, old, new, portAllocator)
}

func (o *onDemandXdsStarter) startEmbeddedEnvoy(wg *completion.WaitGroup) error {
	var startErr error

	o.envoyOnce.Do(func() {
		// Start embedded Envoy on first invocation
		_, startErr = startEmbeddedEnvoy(o.runDir, option.Config.EnvoyLogPath, 0)

		// Add Prometheus listener if the port is (properly) configured
		if option.Config.ProxyPrometheusPort < 0 || option.Config.ProxyPrometheusPort > 65535 {
			log.WithField(logfields.Port, option.Config.ProxyPrometheusPort).Error("Envoy: Invalid configured proxy-prometheus-port")
		} else if option.Config.ProxyPrometheusPort != 0 {
			// We could do this in the bootstrap config as with the Envoy DaemonSet,
			// but then a failure to bind to the configured port would fail starting Envoy.
			o.XDSServer.AddMetricsListener(uint16(option.Config.ProxyPrometheusPort), wg)
		}
	})

	return startErr
}
