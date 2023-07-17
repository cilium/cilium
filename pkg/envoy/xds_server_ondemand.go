// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

type onDemandXdsStarter struct {
	XDSServer

	runDir      string
	adminClient *EnvoyAdminClient
	envoyOnce   sync.Once
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

// requiredEnvoyVersionSHA is set during build
// Running Envoy version will be checked against `requiredEnvoyVersionSHA`.
// By default, cilium-agent will fail to start if there is a version mismatch.
var requiredEnvoyVersionSHA string

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

		if !option.Config.DisableEnvoyVersionCheck {
			if err := o.checkEnvoyVersion(); err != nil {
				log.WithError(err).Error("Envoy: Version check failed")
			}
		}
	})

	return startErr
}

func (o *onDemandXdsStarter) checkEnvoyVersion() error {
	const versionRetryAttempts = 20
	const versionRetryWait = 500 * time.Millisecond

	// Retry is necessary because Envoy might not be ready yet
	for i := 0; i <= versionRetryAttempts; i++ {
		envoyVersion, err := o.adminClient.GetEnvoyVersion()
		if err != nil {
			if i < versionRetryAttempts {
				log.Info("Envoy: Unable to retrieve Envoy version - retry")
				time.Sleep(versionRetryWait)
				continue
			}
			return fmt.Errorf("failed to retrieve Envoy version: %w", err)
		}

		log.Infof("Envoy: Version %s", envoyVersion)

		// Make sure Envoy version matches ours
		if !strings.HasPrefix(envoyVersion, requiredEnvoyVersionSHA) {
			log.Errorf("Envoy: Envoy version %s does not match with required version %s, aborting.",
				envoyVersion, requiredEnvoyVersionSHA)
		}

		log.Debugf("Envoy: Envoy version %s is matching required version %s", envoyVersion, requiredEnvoyVersionSHA)
		return nil
	}

	return nil
}
