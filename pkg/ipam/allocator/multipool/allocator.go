// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var subsysLogAttr = []any{logfields.LogSubsys, "ipam-allocator-multi-pool"}

// Allocator implements allocator.AllocatorProvider
type Allocator struct {
	poolAlloc *PoolAllocator
	logger    *slog.Logger
}

func (a *Allocator) Init(ctx context.Context, logger *slog.Logger) error {
	a.poolAlloc = NewPoolAllocator(logger)
	a.logger = logger.With(subsysLogAttr...)
	return nil
}

func (a *Allocator) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	return NewNodeHandler(a.logger, a.poolAlloc, getterUpdater), nil
}

func (a *Allocator) UpsertPool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error {
	var ipv4CIDRs, ipv6CIDRs []string
	var ipv4MaskSize, ipv6MaskSize int

	if pool.Spec.IPv4 != nil {
		ipv4MaskSize = int(pool.Spec.IPv4.MaskSize)
		ipv4CIDRs = make([]string, len(pool.Spec.IPv4.CIDRs))
		for i, cidr := range pool.Spec.IPv4.CIDRs {
			ipv4CIDRs[i] = string(cidr)
		}
	}

	if pool.Spec.IPv6 != nil {
		ipv6MaskSize = int(pool.Spec.IPv6.MaskSize)
		ipv6CIDRs = make([]string, len(pool.Spec.IPv6.CIDRs))
		for i, cidr := range pool.Spec.IPv6.CIDRs {
			ipv6CIDRs[i] = string(cidr)
		}
	}

	a.logger.Debug(
		"upserting pool",
		logfields.PoolName, pool.Name,
		logfields.IPv4CIDRs, ipv4CIDRs,
		logfields.IPv4MaskSize, ipv4MaskSize,
		logfields.IPv6CIDRs, ipv6CIDRs,
		logfields.IPv6MaskSize, ipv6MaskSize,
	)

	return a.poolAlloc.UpsertPool(
		pool.Name,
		ipv4CIDRs,
		ipv4MaskSize,
		ipv6CIDRs,
		ipv6MaskSize,
	)
}

func (a *Allocator) DeletePool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error {
	a.logger.Debug(
		"deleting pool",
		logfields.PoolName, pool.Name,
	)

	return a.poolAlloc.DeletePool(pool.Name)
}
