// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/promise"
)

type hostEndpointResolver promise.Resolver[*endpoint.Endpoint]

func newHostEndpointPromise() (hostEndpointResolver, endpointstate.HostEndpointPromise) {
	resolver, ready := promise.New[*endpoint.Endpoint]()
	return resolver, ready
}

type hostEndpointParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup job.Group

	EndpointCreator        endpointcreator.EndpointCreator
	EndpointManager        endpointmanager.EndpointManager
	EndpointRestorePromise promise.Promise[endpointstate.Restorer]
	HostEndpointResolver   hostEndpointResolver
}

type hostEndpointCreator struct {
	logger                 *slog.Logger
	endpointCreator        endpointcreator.EndpointCreator
	endpointManager        endpointmanager.EndpointManager
	endpointRestorePromise promise.Promise[endpointstate.Restorer]
	hostEndpointResolver   hostEndpointResolver
}

func registerHostEndpoint(params hostEndpointParams) {
	creator := &hostEndpointCreator{
		logger:                 params.Logger,
		endpointCreator:        params.EndpointCreator,
		endpointManager:        params.EndpointManager,
		endpointRestorePromise: params.EndpointRestorePromise,
		hostEndpointResolver:   params.HostEndpointResolver,
	}

	params.JobGroup.Add(job.OneShot("init-host-endpoint", func(ctx context.Context, health cell.Health) error {
		ep, err := creator.createHostEndpoint(ctx, health)
		if err != nil {
			creator.hostEndpointResolver.Reject(err)
			return err
		}

		creator.hostEndpointResolver.Resolve(ep)
		return nil
	}, job.WithShutdown()))
}

func (c *hostEndpointCreator) createHostEndpoint(ctx context.Context, health cell.Health) (*endpoint.Endpoint, error) {
	health.OK("Wait for endpoint restoration")
	r, err := c.endpointRestorePromise.Await(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to wait for endpoint restorer promise: %w", err)
	}

	if err := r.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return nil, fmt.Errorf("failed to wait for endpoint restoration: %w", err)
	}

	health.OK("Start initialization")

	if ep := c.endpointManager.GetHostEndpoint(); ep != nil {
		c.logger.Info("Initializing labels on existing host endpoint")
		c.endpointManager.InitHostEndpointLabels(ctx)
		return ep, nil
	}

	c.logger.Info("Creating host endpoint")
	if err := c.endpointCreator.AddHostEndpoint(ctx); err != nil {
		return nil, fmt.Errorf("unable to create host endpoint: %w", err)
	}

	ep := c.endpointManager.GetHostEndpoint()
	if ep == nil {
		return nil, fmt.Errorf("host endpoint is unavailable after creation")
	}

	return ep, nil
}
