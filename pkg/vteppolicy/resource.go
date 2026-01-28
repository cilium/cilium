// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type Policy = v2alpha1.CiliumVtepPolicy

func newPolicyResource(lc cell.Lifecycle, c client.Clientset) resource.Resource[*Policy] {
	if !c.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherFromTyped(c.CiliumV2alpha1().CiliumVtepPolicies())
	return resource.New[*Policy](lc, lw, nil)
}
