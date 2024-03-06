// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"slices"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

// CanAdvertisePodCIDR returns true if the provided IPAM mode is supported for
// advertising PodCIDR
func CanAdvertisePodCIDR(ipam string) bool {
	supportedIPAMs := []string{
		ipamOption.IPAMKubernetes,
		ipamOption.IPAMClusterPool,
	}
	return slices.Contains(supportedIPAMs, ipam)
}
