// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"log/slog"
	"net"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/ipam/podippool"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

var _ Allocator = (*multiPoolAllocator)(nil)

type MultiPoolAllocatorParams struct {
	Logger *slog.Logger

	IPv4Enabled          bool
	IPv6Enabled          bool
	CiliumNodeUpdateRate time.Duration
	PreAllocPools        map[string]string

	Node           agentK8s.LocalCiliumNodeResource
	LocalNodeStore *node.LocalNodeStore
	CNClient       cilium_v2.CiliumNodeInterface
	JobGroup       job.Group

	DB                        *statedb.DB
	PodIPPools                statedb.Table[podippool.LocalPodIPPool]
	OnlyMasqueradeDefaultPool bool
}

type multiPoolAllocator struct {
	manager *multiPoolManager
	family  Family
}

func newMultiPoolAllocators(p MultiPoolAllocatorParams) (Allocator, Allocator) {
	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:                    p.Logger,
		IPv4Enabled:               p.IPv4Enabled,
		IPv6Enabled:               p.IPv6Enabled,
		CiliumNodeUpdateRate:      p.CiliumNodeUpdateRate,
		PreAllocPools:             p.PreAllocPools,
		Node:                      p.Node,
		CNClient:                  p.CNClient,
		JobGroup:                  p.JobGroup,
		DB:                        p.DB,
		PodIPPools:                p.PodIPPools,
		OnlyMasqueradeDefaultPool: p.OnlyMasqueradeDefaultPool,
	})

	startLocalNodeAllocCIDRsSync(p.IPv4Enabled, p.IPv6Enabled, p.JobGroup, p.Node, p.LocalNodeStore)

	// wait for local node to be updated to avoid propagating spurious updates.
	waitForLocalNodeUpdate(p.Logger, mgr)

	return &multiPoolAllocator{
			manager: mgr,
			family:  IPv4,
		}, &multiPoolAllocator{
			manager: mgr,
			family:  IPv6,
		}
}

func (c *multiPoolAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(ip, owner, pool, c.family, false)
}

func (c *multiPoolAllocator) Release(ip net.IP, pool Pool) error {
	return c.manager.releaseIP(ip, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateNext(owner, pool, c.family, false)
}

func (c *multiPoolAllocator) Dump() (map[Pool]map[string]string, string) {
	return c.manager.dump(c.family)
}

func (c *multiPoolAllocator) Capacity() uint64 {
	var capacity uint64
	for _, pool := range c.manager.pools {
		var p *podCIDRPool
		switch c.family {
		case IPv4:
			p = pool.v4
		case IPv6:
			p = pool.v6
		}
		if p == nil {
			continue
		}
		capacity += uint64(p.capacity())
	}
	return uint64(capacity)
}

func (c *multiPoolAllocator) RestoreFinished() {
	c.manager.restoreFinished(c.family)
}

func waitForLocalNodeUpdate(logger *slog.Logger, mgr *multiPoolManager) {
	for {
		select {
		case <-mgr.localNodeUpdated():
			return
		case <-time.After(5 * time.Second):
			logger.Info("Waiting for local CiliumNode resource to synchronize local node store")
		}
	}
}

func startLocalNodeAllocCIDRsSync(
	enableIPv4, enableIPv6 bool,
	jobGroup job.Group,
	localNode agentK8s.LocalCiliumNodeResource,
	localNodeStore *node.LocalNodeStore,
) {
	jobGroup.Add(
		job.Observer(
			"multi-pool-local-node-syncer",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				no := nodeTypes.ParseCiliumNode(ev.Object)
				localNodeStore.Update(func(n *node.LocalNode) {
					if enableIPv4 && no.IPv4AllocCIDR != nil {
						n.IPv4AllocCIDR = no.IPv4AllocCIDR
						n.IPv4SecondaryAllocCIDRs = no.IPv4SecondaryAllocCIDRs
					}
					if enableIPv6 && no.IPv6AllocCIDR != nil {
						n.IPv6AllocCIDR = no.IPv6AllocCIDR
						n.IPv6SecondaryAllocCIDRs = no.IPv6SecondaryAllocCIDRs
					}
				})

				return nil
			},
			localNode,
		),
	)
}
