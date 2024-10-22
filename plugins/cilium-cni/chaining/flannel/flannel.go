// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flannel

import (
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	genericveth "github.com/cilium/cilium/plugins/cilium-cni/chaining/generic-veth"
)

func init() {
	chainingapi.Register("flannel", &genericveth.GenericVethChainer{})
}
