// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var subsysLogAttr = []any{logfields.LogSubsys, "ipam-allocator-multi-pool"}

// Allocator implements allocator.AllocatorProvider
type Allocator struct {
	poolAlloc *PoolAllocator
	logger    *slog.Logger
}

type PoolCIDRWithReserved struct {
	CIDR          string
	ReservedRange string // "10.0.0.1-10.0.0.99"
}

func (a *Allocator) Init(ctx context.Context, logger *slog.Logger, _ *metrics.Registry) error {
	a.poolAlloc = NewPoolAllocator(logger)
	a.logger = logger.With(subsysLogAttr...)
	return nil
}

func (a *Allocator) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater, _ *metrics.Registry) (allocator.NodeEventHandler, error) {
	return NewNodeHandler(a.logger, a.poolAlloc, getterUpdater), nil
}

func (a *Allocator) UpsertPool(ctx context.Context, pool *cilium_v2.CiliumPodIPPool) error {
	var ipv4CIDRs, ipv6CIDRs []PoolCIDRWithReserved
	var ipv4MaskSize, ipv6MaskSize int

	if pool.Spec.IPv4 != nil {
		ipv4MaskSize = int(pool.Spec.IPv4.MaskSize)
		ipv4CIDRs = make([]PoolCIDRWithReserved, 0, len(pool.Spec.IPv4.CIDRs))
		for _, cidr := range pool.Spec.IPv4.CIDRs {
			ipv4CIDRs = append(ipv4CIDRs, PoolCIDRWithReserved{
				CIDR:          cidr.CIDR,
				ReservedRange: cidr.ReservedRange,
			})
		}
	}

	if pool.Spec.IPv6 != nil {
		ipv6MaskSize = int(pool.Spec.IPv6.MaskSize)
		ipv6CIDRs = make([]PoolCIDRWithReserved, 0, len(pool.Spec.IPv6.CIDRs))
		for _, cidr := range pool.Spec.IPv6.CIDRs {
			ipv6CIDRs = append(ipv6CIDRs, PoolCIDRWithReserved{
				CIDR:          cidr.CIDR,
				ReservedRange: cidr.ReservedRange,
			})
		}
	}

	a.logger.Debug(
		"upserting pool",
		logfields.PoolName, pool.Name,
		logfields.IPv4CIDRs, ipv4CIDRs,
		logfields.IPv4MaskSize, ipv4MaskSize,
		logfields.IPv6CIDRs, ipv6CIDRs,
		logfields.IPv6MaskSize, ipv6MaskSize,
		logfields.Selector, pool.Spec.PodSelector,
	)

	return a.poolAlloc.UpsertPool(
		pool.Name,
		ipv4CIDRs,
		ipv4MaskSize,
		ipv6CIDRs,
		ipv6MaskSize,
	)
}

func (a *Allocator) DeletePool(ctx context.Context, pool *cilium_v2.CiliumPodIPPool) error {
	a.logger.Debug(
		"deleting pool",
		logfields.PoolName, pool.Name,
	)

	return a.poolAlloc.DeletePool(pool.Name)
}
