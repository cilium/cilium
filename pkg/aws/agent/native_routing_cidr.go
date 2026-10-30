// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// autoDetectNativeRoutingCIDR either validates an existing native routing CIDR
// configuration against the VPC CIDRs of the node, or uses the VPC primary
// CIDR as the autodetected native routing CIDR.
//
// It records the VPC CIDRs as the subnets pod IPs are allocated from: in ENI mode,
// there is no node PodCIDR, so this is what IPsec uses to build its XFRM policies.
//
// When IPv4 is enabled, vpcCIDRs must be non-empty and have the VPC primary
// CIDR as its first element, as GetVPCIPv4CIDRs guarantees.
//
// Returns an error if the configured native routing CIDR overlaps no VPC CIDR.
func autoDetectNativeRoutingCIDR(
	logger *slog.Logger,
	vpcCIDRs []netip.Prefix,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) error {
	var (
		podSubnets   []netip.Prefix
		autodetected netip.Prefix
	)

	if conf.EnableIPv4 {
		podSubnets = slices.Clone(vpcCIDRs)

		if nativeCIDR := conf.IPv4NativeRoutingCIDR; nativeCIDR.IsValid() {
			// Accept the configured native routing CIDR as long as it overlaps
			// one of the VPC CIDRs.
			if !slices.ContainsFunc(vpcCIDRs, func(c netip.Prefix) bool {
				return iputil.LaminarCIDRsOverlap(nativeCIDR, c)
			}) {
				return fmt.Errorf("configured --%s %s overlaps none of the VPC CIDRs %v",
					option.IPv4NativeRoutingCIDR, nativeCIDR, vpcCIDRs)
			}

			logger.Info(
				"Native routing CIDR overlaps a VPC CIDR, ignoring autodetected VPC CIDRs.",
				logfields.VPCCIDR, vpcCIDRs,
				option.IPv4NativeRoutingCIDR, nativeCIDR,
			)
			podSubnets = append(podSubnets, nativeCIDR)
		} else {
			autodetected = vpcCIDRs[0]
			logger.Info(
				"Using autodetected VPC primary CIDR as native routing CIDR.",
				logfields.VPCCIDR, autodetected,
			)
		}
	}

	// There is currently no IPv6 VPC CIDR autodetection: vpcCIDRs only carries the IPv4 CIDR block
	// associations, so the only IPv6 pod subnet that can ever be known is the user-supplied one.
	if nativeCIDR := conf.IPv6NativeRoutingCIDR; nativeCIDR.IsValid() {
		podSubnets = append(podSubnets, nativeCIDR)
	}

	localNodeStore.Update(func(n *node.LocalNode) {
		if autodetected.IsValid() {
			n.Local.IPv4NativeRoutingCIDR = autodetected
		}
		n.SetPodSubnets(podSubnets)
	})
	return nil
}
