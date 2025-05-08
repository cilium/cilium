// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restoration

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module(
	"endpoint-restoration",
	"Endpoint restoration process logic",

	cell.Provide(newEndpointRestorer),

	cell.Provide(promise.New[endpointstate.EndpointsRestored]),
	cell.Provide(promise.New[endpointstate.InitialPoliciesComputed]),
	cell.Invoke(registerEndpointPromiseResolvers),
)

func registerEndpointPromiseResolvers(jobGroup job.Group, endpointRestorer *EndpointRestorer, endpointsRestoredResolver promise.Resolver[endpointstate.EndpointsRestored], initialPoliciesComputedResolver promise.Resolver[endpointstate.InitialPoliciesComputed]) {
	jobGroup.Add(job.OneShot("wait-for-endpoint-restore", func(ctx context.Context, health cell.Health) error {
		if err := endpointRestorer.waitForEndpointRestore(ctx); err != nil {
			endpointsRestoredResolver.Reject(err)
			return err
		}

		endpointsRestoredResolver.Resolve(endpointstate.EndpointsRestored{})
		return nil
	}))

	jobGroup.Add(job.OneShot("wait-for-initial-policy-computation", func(ctx context.Context, health cell.Health) error {
		if err := endpointRestorer.waitForInitialPolicy(ctx); err != nil {
			initialPoliciesComputedResolver.Reject(err)
			return err
		}

		initialPoliciesComputedResolver.Resolve(endpointstate.InitialPoliciesComputed{})
		return nil
	}))
}
