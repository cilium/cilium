// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sutils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

var resourcesCell = cell.Module(
	"resources",
	"Resources",
	cell.Provide(
		func(lc hive.Lifecycle, c k8sClient.Clientset) (resource.Resource[*slim_core_v1.Service], error) {
			optsModifier, err := k8sutils.GetServiceListOptionsModifier(option.Config)
			if err != nil {
				return nil, err
			}
			return resource.New[*slim_core_v1.Service](
				lc,
				k8sutils.ListerWatcherWithModifier(
					k8sutils.ListerWatcherFromTyped[*slim_core_v1.ServiceList](c.Slim().CoreV1().Services("")),
					optsModifier),
			), nil
		},
		func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool] {
			return resource.New[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool](
				lc,
				k8sutils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList](c.CiliumV2alpha1().CiliumLoadBalancerIPPools()),
			)
		},
	),
)

type SharedResources struct {
	cell.In

	Services   resource.Resource[*slim_core_v1.Service]
	CLBIPPools resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
}
