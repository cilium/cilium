// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type Policy = v2.CiliumEgressGatewayPolicy

func newPolicyResource(lc cell.Lifecycle, c client.Clientset) resource.Resource[*Policy] {
	if !c.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherFromTyped[*v2.CiliumEgressGatewayPolicyList](c.CiliumV2().CiliumEgressGatewayPolicies())
	return resource.New[*Policy](lc, lw)
}
