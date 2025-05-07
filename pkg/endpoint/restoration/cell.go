// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restoration

import (
	"context"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module(
	"endpoint-restoration",
	"Endpoint restoration process logic",

	cell.Provide(
		promise.New[endpointstate.EndpointsRestored],
		promise.New[endpointstate.InitialPoliciesComputed],
		newEndpointRestorer,
	),
	cell.Invoke(registerEndpointStateResolvers),
)

func registerEndpointStateResolvers(lc cell.Lifecycle, endpointRestorer *EndpointRestorer, endpointsRestoredResolver promise.Resolver[endpointstate.EndpointsRestored], initialPoliciesComputedResolver promise.Resolver[endpointstate.InitialPoliciesComputed]) {
	var wgEndpointsRestored sync.WaitGroup
	var wgInitialPoliciesComputed sync.WaitGroup

	ctx, cancelCtx := context.WithCancel(context.Background())

	lc.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			wgEndpointsRestored.Add(1)
			go func() {
				defer wgEndpointsRestored.Done()
				if err := endpointRestorer.waitForEndpointRestore(ctx); err != nil {
					endpointsRestoredResolver.Reject(err)
				} else {
					endpointsRestoredResolver.Resolve(endpointstate.EndpointsRestored{})
				}
			}()
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			wgEndpointsRestored.Wait()
			return nil
		},
	})

	lc.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			wgInitialPoliciesComputed.Add(1)
			go func() {
				defer wgInitialPoliciesComputed.Done()
				if err := endpointRestorer.waitForInitialPolicy(ctx); err != nil {
					initialPoliciesComputedResolver.Reject(err)
				} else {
					initialPoliciesComputedResolver.Resolve(endpointstate.InitialPoliciesComputed{})
				}
			}()
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			cancelCtx()
			wgInitialPoliciesComputed.Wait()
			return nil
		},
	})
}
