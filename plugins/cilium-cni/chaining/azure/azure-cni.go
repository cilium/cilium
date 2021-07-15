// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package azure

import (
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/chaining/generic-veth"
)

func init() {
	chainingapi.Register("azure", &genericveth.GenericVethChainer{})
}
