// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

type onDemandXdsStarter struct {
	XDSServer

	logger                         *slog.Logger
	runDir                         string
	adsMode                        bool
	envoyLogPath                   string
	envoyDefaultLogLevel           string
	envoyNodeLocalityEnabled       bool
	envoyBaseID                    uint64
	keepCapNetBindService          bool
	metricsListenerPort            int
	adminListenerPort              int
	connectTimeout                 int64
	maxActiveDownstreamConnections int64
	maxRequestsPerConnection       uint32
	maxConnectionDuration          time.Duration
	idleTimeout                    time.Duration
	maxConcurrentRetries           uint32
	maxConnections                 uint32
	maxRequests                    uint32
	maxPendingRequests             uint32
	localNodeStore                 *node.LocalNodeStore

	envoyOnce sync.Once
}

var _ XDSServer = &onDemandXdsStarter{}

func (o *onDemandXdsStarter) AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error {
	if err := o.startStandaloneEnvoy(ctx, nil); err != nil {
		o.logger.Error("Envoy: Failed to start standalone Envoy proxy on demand",
			logfields.Error, err,
		)
	}

	return o.XDSServer.AddListener(ctx, name, kind, port, isIngress, mayUseOriginalSourceAddr, wg, cb)
}

func (o *onDemandXdsStarter) UpsertEnvoyResources(ctx context.Context, resources xds.Resources, waitGroup *completion.WaitGroup) error {
	if err := o.startStandaloneEnvoy(ctx, nil); err != nil {
		o.logger.Error("Envoy: Failed to start standalone Envoy proxy on demand",
			logfields.Error, err,
		)
	}

	return o.XDSServer.UpsertEnvoyResources(ctx, resources, waitGroup)
}

func (o *onDemandXdsStarter) UpdateEnvoyResources(ctx context.Context, old, new xds.Resources, waitGroup *completion.WaitGroup) error {
	if err := o.startStandaloneEnvoy(ctx, nil); err != nil {
		o.logger.Error("Envoy: Failed to start standalone Envoy proxy on demand",
			logfields.Error, err,
		)
	}

	return o.XDSServer.UpdateEnvoyResources(ctx, old, new, waitGroup)
}

func (o *onDemandXdsStarter) startStandaloneEnvoy(ctx context.Context, wg *completion.WaitGroup) error {
	var startErr error

	o.envoyOnce.Do(func() {
		// Start standalone Envoy on first invocation
		_, startErr = o.startStandaloneEnvoyInternal(standaloneEnvoyConfig{
			adsMode:                        o.adsMode,
			runDir:                         o.runDir,
			logPath:                        o.envoyLogPath,
			defaultLogLevel:                o.envoyDefaultLogLevel,
			nodeLocalityEnabled:            o.envoyNodeLocalityEnabled,
			baseID:                         o.envoyBaseID,
			keepCapNetBindService:          o.keepCapNetBindService,
			connectTimeout:                 o.connectTimeout,
			maxActiveDownstreamConnections: o.maxActiveDownstreamConnections,
			maxRequestsPerConnection:       o.maxRequestsPerConnection,
			maxConnectionDuration:          o.maxConnectionDuration,
			idleTimeout:                    o.idleTimeout,
			maxConcurrentRetries:           o.maxConcurrentRetries,
			maxConnections:                 o.maxConnections,
			maxRequests:                    o.maxRequests,
			maxPendingRequests:             o.maxPendingRequests,
		})

		// Add Prometheus listener if the port is (properly) configured
		if o.metricsListenerPort < 0 || o.metricsListenerPort > 65535 {
			o.logger.Error("Envoy: Invalid configured proxy-prometheus-port",
				logfields.Port, o.metricsListenerPort,
			)
		} else if o.metricsListenerPort != 0 {
			// We could do this in the bootstrap config as with the Envoy DaemonSet,
			// but then a failure to bind to the configured port would fail starting Envoy.
			o.AddMetricsListener(ctx, uint16(o.metricsListenerPort), wg)
		}

		// Add Admin listener if the port is (properly) configured
		if o.adminListenerPort < 0 || o.adminListenerPort > 65535 {
			o.logger.Error("Envoy: Invalid configured proxy-admin-port",
				logfields.Port, o.adminListenerPort,
			)
		} else if o.adminListenerPort != 0 {
			o.AddAdminListener(ctx, uint16(o.adminListenerPort), wg)
		}
	})

	return startErr
}
