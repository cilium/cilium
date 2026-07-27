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
	"github.com/cilium/cilium/pkg/promise"
)

type hostEndpointParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup job.Group

	EndpointCreator        endpointcreator.EndpointCreator
	EndpointManager        endpointmanager.EndpointManager
	EndpointRestorePromise promise.Promise[endpointstate.Restorer]
}

type hostEndpointCreator struct {
	logger                 *slog.Logger
	endpointCreator        endpointcreator.EndpointCreator
	endpointManager        endpointmanager.EndpointManager
	endpointRestorePromise promise.Promise[endpointstate.Restorer]
}

func registerHostEndpoint(params hostEndpointParams) {
	creator := &hostEndpointCreator{
		logger:                 params.Logger,
		endpointCreator:        params.EndpointCreator,
		endpointManager:        params.EndpointManager,
		endpointRestorePromise: params.EndpointRestorePromise,
	}

	params.JobGroup.Add(job.OneShot("init-host-endpoint", creator.createHostEndpoint, job.WithShutdown()))
}

func (c *hostEndpointCreator) createHostEndpoint(ctx context.Context, health cell.Health) error {
	health.OK("Wait for endpoint restoration")
	r, err := c.endpointRestorePromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for endpoint restorer promise: %w", err)
	}

	if err := r.WaitForEndpointRestoreWithoutRegeneration(ctx); err != nil {
		return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
	}

	health.OK("Start initialization")

	if c.endpointManager.HostEndpointExists() {
		c.logger.Info("Initializing labels on existing host endpoint")
		c.endpointManager.InitHostEndpointLabels(ctx)
		return nil
	}

	c.logger.Info("Creating host endpoint")
	if err := c.endpointCreator.AddHostEndpoint(ctx); err != nil {
		return fmt.Errorf("unable to create host endpoint: %w", err)
	}

	return nil
}
