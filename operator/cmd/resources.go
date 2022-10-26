// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

var resourcesCell = cell.Module(
	"resources",
	cell.Provide(
		func(lc hive.Lifecycle, c k8sClient.Clientset) (resource.Resource[*slim_core_v1.Service], error) {
			optsModifier, err := utils.GetServiceListOptionsModifier(option.Config)
			if err != nil {
				return nil, err
			}
			return resource.New[*slim_core_v1.Service](
				lc,
				utils.ListerWatcherWithModifier(
					utils.ListerWatcherFromTyped[*slim_core_v1.ServiceList](c.Slim().CoreV1().Services("")),
					optsModifier),
				resource.WithErrorHandler(resource.AlwaysRetry),
				resource.WithRateLimiter(errorRateLimiter),
			), nil
		},
		func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool] {
			return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](
				lc,
				utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](c.CiliumV2alpha1().CiliumLoadBalancerIPPools()),
				resource.WithErrorHandler(resource.AlwaysRetry),
				resource.WithRateLimiter(errorRateLimiter),
			)
		},
	),
)

type SharedResources struct {
	cell.In

	Services   resource.Resource[*slim_core_v1.Service]
	CLBIPPools resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
}

func errorRateLimiter() workqueue.RateLimiter {
	// This rate limiter will retry in the following pattern
	// 250ms, 500ms, 1s, 2s, 4s, 8s, 16s, 32s, .... max 5m
	return workqueue.NewItemExponentialFailureRateLimiter(250*time.Millisecond, 5*time.Minute)
}
