// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clusterpool

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"
	"github.com/cilium/cilium/pkg/ipam/allocator/podcidr"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

var subsysLogAttr = []any{logfields.LogSubsys, "ipam-allocator-clusterpool"}

// AllocatorOperator is an implementation of IPAM allocator interface for Cilium
// IPAM.
type AllocatorOperator struct {
	rootLogger           *slog.Logger
	logger               *slog.Logger
	v4CIDRSet, v6CIDRSet []cidralloc.CIDRAllocator

	// ClusterPoolIPv4CIDR is the cluster's IPv4 CIDR(s) to allocate
	// individual PodCIDR ranges from.
	ClusterPoolIPv4CIDR []string

	// ClusterPoolIPv4MaskSize is the IPv4 podCIDR mask size per node.
	ClusterPoolIPv4MaskSize int

	// ClusterPoolIPv6CIDR is the cluster's IPv6 CIDR(s) to allocate
	// individual PodCIDR ranges from.
	ClusterPoolIPv6CIDR []string

	// ClusterPoolIPv6MaskSize is the IPv6 podCIDR mask size per node.
	ClusterPoolIPv6MaskSize int
}

// Init sets up Cilium allocator based on given options
func (a *AllocatorOperator) Init(ctx context.Context, logger *slog.Logger) error {
	a.rootLogger = logger
	a.logger = logger.With(subsysLogAttr...)
	if option.Config.EnableIPv4 {
		if len(a.ClusterPoolIPv4CIDR) == 0 {
			return fmt.Errorf("cluster-pool-ipv4-cidr must be provided when using ClusterPool")
		}

		v4Allocators, err := cidralloc.NewCIDRSets(false, a.ClusterPoolIPv4CIDR, a.ClusterPoolIPv4MaskSize)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv4 allocator: %w", err)
		}
		a.v4CIDRSet = v4Allocators
	} else if len(a.ClusterPoolIPv4CIDR) != 0 {
		return fmt.Errorf("cluster-pool-ipv4-cidr must not be set if IPv4 is disabled")
	}

	if option.Config.EnableIPv6 {
		if len(a.ClusterPoolIPv6CIDR) == 0 {
			return fmt.Errorf("cluster-pool-ipv6-cidr must be provided when using ClusterPool")
		}

		v6Allocators, err := cidralloc.NewCIDRSets(true, a.ClusterPoolIPv6CIDR, a.ClusterPoolIPv6MaskSize)
		if err != nil {
			return fmt.Errorf("unable to initialize IPv6 allocator: %w", err)
		}
		a.v6CIDRSet = v6Allocators
	} else if len(a.ClusterPoolIPv6CIDR) != 0 {
		return fmt.Errorf("cluster-pool-ipv6-cidr must not be set if IPv6 is disabled")
	}

	return nil
}

// Start kicks of Operator allocation.
func (a *AllocatorOperator) Start(ctx context.Context, updater ipam.CiliumNodeGetterUpdater, iMetrics trigger.MetricsObserver) (allocator.NodeEventHandler, error) {
	a.logger.Info(
		"Starting ClusterPool IP allocator",
		logfields.IPv4CIDRs, a.ClusterPoolIPv4CIDR,
		logfields.IPv6CIDRs, a.ClusterPoolIPv6CIDR,
	)

	nodeManager := podcidr.NewNodesPodCIDRManager(a.logger, a.v4CIDRSet, a.v6CIDRSet, updater, iMetrics)

	return nodeManager, nil
}
