// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipam/podippool"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const waitForPoolInStateDBTimeout = time.Minute

var MultiPoolAccessor = PoolSpecAccessors{
	FromResource: func(cn *ciliumv2.CiliumNode) types.IPAMPoolSpec {
		return cn.Spec.IPAM.Pools
	},
	ToResource: func(cn *ciliumv2.CiliumNode, spec types.IPAMPoolSpec) bool {
		if !cn.Spec.IPAM.Pools.DeepEqual(&spec) {
			cn.Spec.IPAM.Pools = spec
			return true
		}
		return false
	},
}

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

func newMultiPoolAllocators(ctx context.Context, p MultiPoolAllocatorParams) (Allocator, Allocator, error) {
	preallocMap, err := ParseMultiPoolPreAllocMap(p.PreAllocPools)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid --%s flag value: %w", option.IPAMMultiPoolPreAllocation, err)
	}

	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:                p.Logger,
		IPv4Enabled:           p.IPv4Enabled,
		IPv6Enabled:           p.IPv6Enabled,
		CiliumNodeUpdateRate:  p.CiliumNodeUpdateRate,
		PreallocMap:           preallocMap,
		Node:                  p.Node,
		CNClient:              p.CNClient,
		JobGroup:              p.JobGroup,
		SkipMasqueradeForPool: shouldSkipMasqForPool(p.DB, p.PodIPPools, p.OnlyMasqueradeDefaultPool),
		PoolSpecAccessors:     MultiPoolAccessor,
	})

	waitForAllPools(p.Logger, p.DB, p.PodIPPools, preallocMap)

	allocCIDRsReady := startLocalNodeAllocCIDRsSync(p.IPv4Enabled, p.IPv6Enabled, p.JobGroup, p.Node, p.LocalNodeStore)

	// wait for local node to be updated to avoid propagating spurious updates.
	if err := waitForLocalNodeUpdate(ctx, p.Logger, mgr); err != nil {
		return nil, nil, err
	}
	// Independently wait for the alloc-CIDR observer: it runs in its own job
	// and is not synchronized with mgr.localNodeUpdated().
	if err := waitForLocalNodeAllocCIDRs(ctx, p.Logger, allocCIDRsReady); err != nil {
		return nil, nil, err
	}

	return &multiPoolAllocator{
			manager: mgr,
			family:  IPv4,
		}, &multiPoolAllocator{
			manager: mgr,
			family:  IPv6,
		}, nil
}

func (c *multiPoolAllocator) Allocate(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(addr, owner, pool, c.family, true)
}

func (c *multiPoolAllocator) AllocateWithoutSyncUpstream(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return c.manager.allocateIP(addr, owner, pool, c.family, false)
}

func (c *multiPoolAllocator) Release(addr netip.Addr, pool Pool) error {
	return c.manager.releaseIP(addr, pool, c.family, true)
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
	return c.manager.capacity(c.family)
}

func (c *multiPoolAllocator) RestoreFinished() {
	c.manager.restoreFinished(c.family)
}

func shouldSkipMasqForPool(db *statedb.DB, podIPPools statedb.Table[podippool.LocalPodIPPool], onlyMasqueradeDefaultPool bool) SkipMasqueradeForPoolFn {
	return func(pool Pool) (bool, error) {
		// If the flag is set, skip masquerade for all non-default pools
		if onlyMasqueradeDefaultPool && pool != PoolDefault() {
			return true, nil
		}
		// Lookup the IP pool from stateDB and check if it has the explicit annotations
		podIPPool, _, found := podIPPools.Get(db.ReadTxn(), podippool.ByName(string(pool)))
		if !found {
			return false, fmt.Errorf("IP pool '%s' not found in stateDB table", string(pool))
		}
		if v, ok := podIPPool.Annotations[annotation.IPAMSkipMasquerade]; ok && v == "true" {
			return true, nil
		}
		return false, nil
	}
}

func waitForAllPools(logger *slog.Logger, db *statedb.DB, podIPPools statedb.Table[podippool.LocalPodIPPool], preallocMap preAllocatePerPool) {
	for pool := range preallocMap {
		if !waitForPool(logger, db, podIPPools, pool) {
			return
		}
	}
}

func waitForPool(logger *slog.Logger, db *statedb.DB, podIPPools statedb.Table[podippool.LocalPodIPPool], pool Pool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), waitForPoolInStateDBTimeout)
	defer cancel()

	for {
		txn := db.ReadTxn()
		_, _, dbWatch, found := podIPPools.GetWatch(txn, podippool.ByName(string(pool)))
		if found {
			return true
		}

		select {
		case <-ctx.Done():
			return false
		case <-dbWatch:
			continue
		case <-time.After(5 * time.Second):
			logger.Info(
				"Waiting for pod cidr pool to become available in stateDB",
				logfields.PoolName, pool,
				logfields.HelpMessage, "Check if cilium-operator pod is running and does not have any warnings or error messages.",
			)
		}
	}
}

// waitForLocalNodeUpdate blocks until the multi-pool manager has synchronized
// the local node store with the CiliumNode resource. It returns an error if ctx
// is cancelled before that.
func waitForLocalNodeUpdate(ctx context.Context, logger *slog.Logger, mgr *multiPoolManager) error {
	for {
		select {
		case <-mgr.localNodeUpdated():
			return nil
		case <-ctx.Done():
			return fmt.Errorf("waiting for the local CiliumNode resource to synchronize the local node store: %w", ctx.Err())
		case <-time.After(5 * time.Second):
			logger.Info("Waiting for local CiliumNode resource to synchronize local node store")
		}
	}
}

// waitForLocalNodeAllocCIDRs blocks until the multi-pool-local-node-syncer
// observer has processed its first CiliumNode upsert event. This synchronizes
// the observer with the multi-pool manager's own CN-events handler so callers
// that subsequently read the local node store see state derived from at least
// the same first event the manager saw.
//
// It returns an error if ctx is cancelled before that. ctx is the hive
// start-hook context, whose timeout bounds the wait.
func waitForLocalNodeAllocCIDRs(ctx context.Context, logger *slog.Logger, ready <-chan struct{}) error {
	for {
		select {
		case <-ready:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("waiting for the multi-pool local node syncer to process the first CiliumNode event: %w", ctx.Err())
		case <-time.After(5 * time.Second):
			logger.Info("Waiting for the multi-pool local node syncer to process the first CiliumNode event")
		}
	}
}

// startLocalNodeAllocCIDRsSync starts a CiliumNode observer that mirrors the
// alloc CIDRs (Spec.IPAM.PodCIDRs / Spec.IPAM.Pools.Allocated) into the local
// node store.
//
// The returned channel is closed once the observer has processed its first
// Upsert event. Callers must wait on it before reading the local node store,
// otherwise they may race with this observer (which runs in a separate job
// from the multi-pool manager and is not synchronized with
// mgr.localNodeUpdated()).
func startLocalNodeAllocCIDRsSync(
	enableIPv4, enableIPv6 bool,
	jobGroup job.Group,
	localNode agentK8s.LocalCiliumNodeResource,
	localNodeStore *node.LocalNodeStore,
) <-chan struct{} {
	ready := make(chan struct{})
	var once sync.Once
	jobGroup.Add(
		job.Observer(
			"multi-pool-local-node-syncer",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				no := k8s.ParseCiliumNode(
					ev.Object,
					// The rest of the function does not use the cluster name/id, so let's
					// just pass a dummy value to avoid having to propagate a ClusterInfo
					cmtypes.ClusterInfo{ID: 0, Name: "should-not-be-used"},
				)
				localNodeStore.Update(func(n *node.LocalNode) {
					if enableIPv4 && no.IPv4AllocCIDR.IsValid() {
						n.IPv4AllocCIDR = no.IPv4AllocCIDR
						n.IPv4SecondaryAllocCIDRs = no.IPv4SecondaryAllocCIDRs
					}
					if enableIPv6 && no.IPv6AllocCIDR.IsValid() {
						n.IPv6AllocCIDR = no.IPv6AllocCIDR
						n.IPv6SecondaryAllocCIDRs = no.IPv6SecondaryAllocCIDRs
					}
				})

				once.Do(func() { close(ready) })
				return nil
			},
			localNode,
		),
	)
	return ready
}
