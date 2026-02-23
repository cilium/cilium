// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type ingressEndpointCreatorParams struct {
	cell.In

	Logger       *slog.Logger
	DaemonConfig *option.DaemonConfig

	JobGroup job.Group

	EndpointCreator        endpointcreator.EndpointCreator
	EndpointManager        endpointmanager.EndpointManager
	EndpointRestorePromise promise.Promise[endpointstate.Restorer]
	LocalNodeStore         *node.LocalNodeStore
}

type ingressEndpointCreator struct {
	logger                 *slog.Logger
	endpointCreator        endpointcreator.EndpointCreator
	endpointManager        endpointmanager.EndpointManager
	endpointRestorePromise promise.Promise[endpointstate.Restorer]
	localNodeStore         *node.LocalNodeStore

	ipv4Enabled bool
	ipv6Enabled bool
}

func registerIngressEndpoint(params ingressEndpointCreatorParams) {
	if !params.DaemonConfig.EnableEnvoyConfig {
		return
	}

	creator := &ingressEndpointCreator{
		logger:                 params.Logger,
		endpointCreator:        params.EndpointCreator,
		endpointManager:        params.EndpointManager,
		endpointRestorePromise: params.EndpointRestorePromise,
		localNodeStore:         params.LocalNodeStore,
		ipv4Enabled:            params.DaemonConfig.IPv4Enabled(),
		ipv6Enabled:            params.DaemonConfig.IPv6Enabled(),
	}

	params.JobGroup.Add(job.OneShot("init-ingress-endpoint", creator.createIngressEndpoint, job.WithShutdown()))
}

func (c *ingressEndpointCreator) createIngressEndpoint(ctx context.Context, health cell.Health) error {
	health.OK("Wait for endpoint restoration")
	r, err := c.endpointRestorePromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for endpoint restorer promise: %w", err)
	}

	if err := r.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
	}

	health.OK("Start initialization")

	if c.endpointManager.IngressEndpointExists() {
		c.logger.Debug("Ingress endpoint already exists")
		return nil
	}

	// Creating Ingress Endpoint depends on the Ingress IPs having been
	// allocated first. This happens earlier in the agent bootstrap.
	ln, err := c.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	if (c.ipv4Enabled && len(ln.IPv4IngressIP) == 0) ||
		(c.ipv6Enabled && len(ln.IPv6IngressIP) == 0) {
		msg := "Ingress IPs are not available, skipping creation of the Ingress Endpoint: Policy enforcement on Cilium Ingress will not work as expected."
		c.logger.Warn(msg)
		health.Degraded(msg, nil)
		return nil
	}

	c.logger.Info("Creating ingress endpoint")
	if err := c.endpointCreator.AddIngressEndpoint(ctx); err != nil {
		return fmt.Errorf("unable to create ingress endpoint: %w", err)
	}

	return nil
}
