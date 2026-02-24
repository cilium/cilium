// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

type onDemandXdsStarter struct {
	XDSServer

	logger                   *slog.Logger
	runDir                   string
	envoyLogPath             string
	envoyDefaultLogLevel     string
	envoyBaseID              uint64
	keepCapNetBindService    bool
	metricsListenerPort      int
	adminListenerPort        int
	connectTimeout           int64
	maxRequestsPerConnection uint32
	maxConnectionDuration    time.Duration
	idleTimeout              time.Duration
	maxConcurrentRetries     uint32

	envoyOnce sync.Once
}

var _ XDSServer = &onDemandXdsStarter{}

func (o *onDemandXdsStarter) AddListener(name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	if err := o.startEmbeddedEnvoy(nil); err != nil {
		o.logger.Error("Envoy: Failed to start embedded Envoy proxy on demand",
			logfields.Error, err,
		)
	}

	return o.XDSServer.AddListener(name, kind, port, isIngress, mayUseOriginalSourceAddr, wg, cb)
}

func (o *onDemandXdsStarter) UpsertEnvoyResources(ctx context.Context, resources Resources) error {
	if err := o.startEmbeddedEnvoy(nil); err != nil {
		o.logger.Error("Envoy: Failed to start embedded Envoy proxy on demand",
			logfields.Error, err,
		)
	}

	return o.XDSServer.UpsertEnvoyResources(ctx, resources)
}

func (o *onDemandXdsStarter) UpdateEnvoyResources(ctx context.Context, old, new Resources) error {
	if err := o.startEmbeddedEnvoy(nil); err != nil {
		o.logger.Error("Envoy: Failed to start embedded Envoy proxy on demand",
			logfields.Error, err,
		)
	}

	return o.XDSServer.UpdateEnvoyResources(ctx, old, new)
}

func (o *onDemandXdsStarter) startEmbeddedEnvoy(wg *completion.WaitGroup) error {
	var startErr error

	o.envoyOnce.Do(func() {
		// Start embedded Envoy on first invocation
		_, startErr = o.startEmbeddedEnvoyInternal(embeddedEnvoyConfig{
			runDir:                   o.runDir,
			logPath:                  o.envoyLogPath,
			defaultLogLevel:          o.envoyDefaultLogLevel,
			baseID:                   o.envoyBaseID,
			keepCapNetBindService:    o.keepCapNetBindService,
			connectTimeout:           o.connectTimeout,
			maxRequestsPerConnection: o.maxRequestsPerConnection,
			maxConnectionDuration:    o.maxConnectionDuration,
			idleTimeout:              o.idleTimeout,
			maxConcurrentRetries:     o.maxConcurrentRetries,
		})

		// Add Prometheus listener if the port is (properly) configured
		if o.metricsListenerPort < 0 || o.metricsListenerPort > 65535 {
			o.logger.Error("Envoy: Invalid configured proxy-prometheus-port",
				logfields.Port, o.metricsListenerPort,
			)
		} else if o.metricsListenerPort != 0 {
			// We could do this in the bootstrap config as with the Envoy DaemonSet,
			// but then a failure to bind to the configured port would fail starting Envoy.
			o.AddMetricsListener(uint16(o.metricsListenerPort), wg)
		}

		// Add Admin listener if the port is (properly) configured
		if o.adminListenerPort < 0 || o.adminListenerPort > 65535 {
			o.logger.Error("Envoy: Invalid configured proxy-admin-port",
				logfields.Port, o.adminListenerPort,
			)
		} else if o.adminListenerPort != 0 {
			o.AddAdminListener(uint16(o.adminListenerPort), wg)
		}
	})

	return startErr
}
