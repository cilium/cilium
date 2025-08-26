// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	genericveth "github.com/cilium/cilium/plugins/cilium-cni/chaining/generic-veth"
)

func init() {
	chainingapi.Register("aws-cni", &genericveth.GenericVethChainer{})
}
