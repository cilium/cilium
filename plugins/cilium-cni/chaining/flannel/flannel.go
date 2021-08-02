// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

package flannel

import (
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/chaining/generic-veth"
)

func init() {
	chainingapi.Register("flannel", &genericveth.GenericVethChainer{})
}
