// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type Policy = v2.CiliumEgressGatewayPolicy

func newPolicyResource(lc cell.Lifecycle, c client.Clientset, mp workqueue.MetricsProvider) resource.Resource[*Policy] {
	if !c.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherFromTyped(c.CiliumV2().CiliumEgressGatewayPolicies())
	return resource.New[*Policy](lc, lw, mp)
}
