// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator-multi-pool")

// Allocator implements allocator.AllocatorProvider
type Allocator struct {
	poolAlloc *PoolAllocator
}

func (a *Allocator) Init(ctx context.Context) error {
	a.poolAlloc = NewPoolAllocator()
	return nil
}

func (a *Allocator) Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (allocator.NodeEventHandler, error) {
	return NewNodeHandler(a.poolAlloc, getterUpdater), nil
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

	log.WithFields(logrus.Fields{
		"pool-name":      pool.Name,
		"ipv4-cidrs":     ipv4CIDRs,
		"ipv4-mask-size": ipv4MaskSize,
		"ipv6-cidrs":     ipv6CIDRs,
		"ipv6-mask-size": ipv6MaskSize,
	}).Debug("upserting pool")

	return a.poolAlloc.UpsertPool(
		pool.Name,
		ipv4CIDRs,
		ipv4MaskSize,
		ipv6CIDRs,
		ipv6MaskSize,
	)
}

func (a *Allocator) DeletePool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error {
	log.WithFields(logrus.Fields{
		"pool-name": pool.Name,
	}).Debug("deleting pool")

	return a.poolAlloc.DeletePool(pool.Name)
}
