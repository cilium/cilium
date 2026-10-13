// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package ipam

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// startIPv4EgressAllocator allocates the IPv4 egress pool of the nodes running
// in IPv4 egress-only mode, out of the configured egress CIDRs and without
// involving AWS.
//
// It runs a multi-pool allocator restricted to that pool next to the ENI
// allocator. Both write Spec.IPAM.Pools of the same CiliumNodes, so the
// multi-pool node handler only reads and writes the egress pool, and the ENI
// node manager only considers the default pool. Nodes that do not run in IPv4
// egress-only mode request no egress addresses and get none.
func startIPv4EgressAllocator(p awsParams) {
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			spec, err := parseIPv4EgressPoolSpec(p.AwsCfg.IPv4EgressOnlyCIDRs, p.AwsCfg.IPv4EgressOnlyMaskSize)
			if err != nil {
				return err
			}

			// The egress addresses are only ever handed out by agents running
			// in IPv4 egress-only mode, which get IPv6 from the ENIs.
			alloc := multipool.NewPoolAllocator(p.Logger, true, false)
			if err := multipool.UpsertPool(alloc, defaults.IPAMIPv4EgressPool, spec, nil, false, false); err != nil {
				return fmt.Errorf("unable to create the IPv4 egress pool: %w", err)
			}

			p.Logger.Info(
				"Allocating IPv4 egress-only addresses",
				logfields.CIDRs, spec.CIDRs,
				logfields.PoolName, defaults.IPAMIPv4EgressPool,
			)

			p.JobGroup.Add(job.OneShot(
				"ipv4-egress-cilium-nodes-watcher",
				func(ctx context.Context, _ cell.Health) error {
					nh := multipool.NewNodeHandler(
						"ipam-ipv4-egress-sync",
						p.Logger, alloc, p.Clientset.CiliumV2().CiliumNodes(),
						multipool.SinglePoolAccessor(defaults.IPAMIPv4EgressPool),
						ipam.MultiPoolStatusAccessor,
					)

					// The resync is what tells the allocator that the CIDRs of
					// every node have been restored and new ones can be
					// allocated without handing out the same CIDR twice.
					watchCiliumNodes(ctx, p.CiliumNodes, nh, true)
					nh.Stop()

					return nil
				},
			))

			return nil
		},
	})
}

// parseIPv4EgressPoolSpec builds the spec of the IPv4 egress pool from the
// operator configuration.
func parseIPv4EgressPoolSpec(cidrs []string, maskSize int) (*cilium_api_v2.IPv4PoolSpec, error) {
	if maskSize < 1 || maskSize > 32 {
		return nil, fmt.Errorf("invalid IPv4 egress-only mask size %d, must be between 1 and 32", maskSize)
	}

	spec := &cilium_api_v2.IPv4PoolSpec{MaskSize: uint8(maskSize)}
	for _, c := range cidrs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv4 egress-only CIDR %q: %w", c, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("IPv4 egress-only CIDR %s is not an IPv4 CIDR", prefix)
		}
		if prefix.Bits() > maskSize {
			return nil, fmt.Errorf("IPv4 egress-only CIDR %s is smaller than the mask size /%d", prefix, maskSize)
		}
		spec.CIDRs = append(spec.CIDRs, iputil.PrefixFrom(prefix.Masked()))
	}
	return spec, nil
}
