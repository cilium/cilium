// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/job"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/defaults"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/time"
)

var _ Allocator = (*cloudMultiPoolAllocator)(nil)

// cloudMultiPoolAllocator wraps multiPoolAllocator to enrich AllocationResult
// with the cloud-specific metadata its CloudProvider supplies.
type cloudMultiPoolAllocator struct {
	multiPoolAllocator

	resolver RoutingMetadataResolver
}

// enrichResult completes a successful allocation with the routing metadata the
// resolver reports for it, releasing the reservation if that fails.
func (a *cloudMultiPoolAllocator) enrichResult(result *AllocationResult, err error) (*AllocationResult, error) {
	if err != nil || result == nil {
		return result, err
	}

	// The node is only read by the resolver, so the pointer is handed over
	// as-is: the multi-pool manager replaces it wholesale on every update and
	// deep-copies it before any mutation, so it is effectively immutable.
	enriched, enrichErr := a.ResolveRoutingMetadata(result.IP, result.IPPoolName)
	if enrichErr != nil {
		// The underlying Allocate* call already reserved the IP in the
		// allocator. Release it to avoid leaking the reservation when the
		// caller treats the wrapped error as an allocation failure.
		if relErr := a.multiPoolAllocator.Release(result.IP, result.IPPoolName); relErr != nil {
			return nil, errors.Join(enrichErr, fmt.Errorf("release after enrichment failure: %w", relErr))
		}
		return nil, enrichErr
	}
	return enriched, nil
}

func (a *cloudMultiPoolAllocator) ResolveRoutingMetadata(addr netip.Addr, pool Pool) (*AllocationResult, error) {
	return a.resolver.ResolveRoutingMetadata(a.manager.getNode(), addr, pool)
}

func (a *cloudMultiPoolAllocator) Allocate(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.Allocate(addr, owner, pool))
}

func (a *cloudMultiPoolAllocator) AllocateWithoutSyncUpstream(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.AllocateWithoutSyncUpstream(addr, owner, pool))
}

func (a *cloudMultiPoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.AllocateNext(owner, pool))
}

func (a *cloudMultiPoolAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.AllocateNextWithoutSyncUpstream(owner, pool))
}

// cloudMultiPoolParams contains the parameters for creating the cloud-provider
// backed multi-pool allocators.
type cloudMultiPoolParams struct {
	Logger *slog.Logger

	IPv4Enabled          bool
	IPv6Enabled          bool
	CiliumNodeUpdateRate time.Duration

	Node           agentK8s.LocalCiliumNodeResource
	LocalNodeStore *node.LocalNodeStore
	CNClient       cilium_v2.CiliumNodeInterface
	JobGroup       job.Group

	Provider CloudProvider
}

// newCloudMultiPoolAllocators builds the IPv4 and IPv6 allocators for a cloud
// provider. It blocks until the provider and the multi-pool manager have caught
// up with the state the datapath needs before the first allocation.
//
// Everything that observes the CiliumNode is registered up front, before any of
// the waits below: the provider's jobs, the multi-pool manager and the
// alloc-CIDR syncer all converge on the same event stream, so registering them
// together lets them make progress concurrently instead of serializing their
// startup latencies.
func newCloudMultiPoolAllocators(ctx context.Context, p cloudMultiPoolParams) (ipv4, ipv6 *cloudMultiPoolAllocator, err error) {
	resolver, err := p.Provider.Initialize()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to initialize the %s IPAM provider: %w", p.Provider.Mode(), err)
	}
	if resolver == nil {
		return nil, nil, fmt.Errorf("the %s IPAM provider returned no routing metadata resolver", p.Provider.Mode())
	}

	// Cloud providers allocate out of a single pool, pre-allocated linearly:
	// the operator hands out CIDRs carved from the VPC, so there is no
	// per-pool configuration to parse.
	preallocMap := preAllocatePerPool{
		Pool(defaults.IPAMDefaultIPPool): defaults.IPAMPreAllocation,
	}

	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:               p.Logger,
		IPv4Enabled:          p.IPv4Enabled,
		IPv6Enabled:          p.IPv6Enabled,
		CiliumNodeUpdateRate: p.CiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 p.Node,
		CNClient:             p.CNClient,
		JobGroup:             p.JobGroup,
		PoolSpecAccessors:    p.Provider.PoolSpecAccessors(),
		LinearPreAlloc:       true,
	})

	allocCIDRsReady := startLocalNodeAllocCIDRsSync(p.IPv4Enabled, p.IPv6Enabled, p.JobGroup, p.Node, p.LocalNodeStore)

	// Wait for local node to be updated to avoid propagating spurious updates.
	if err := waitForLocalNodeUpdate(ctx, p.Logger, mgr); err != nil {
		return nil, nil, err
	}
	// Independently wait for the alloc-CIDR observer: it runs in a separate job
	// from the multi-pool manager and is not synchronized with
	// mgr.localNodeUpdated().
	if err := waitForLocalNodeAllocCIDRs(ctx, p.Logger, allocCIDRsReady); err != nil {
		return nil, nil, err
	}
	// Finally wait for the provider's own jobs, which have been running since
	// Initialize.
	if err := p.Provider.WaitReady(ctx); err != nil {
		return nil, nil, fmt.Errorf("the %s IPAM provider did not become ready: %w", p.Provider.Mode(), err)
	}

	newAllocator := func(family Family) *cloudMultiPoolAllocator {
		return &cloudMultiPoolAllocator{
			multiPoolAllocator: multiPoolAllocator{manager: mgr, family: family},
			resolver:           resolver,
		}
	}
	return newAllocator(IPv4), newAllocator(IPv6), nil
}
