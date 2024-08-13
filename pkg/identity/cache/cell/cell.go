// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"log"
	"net"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
)

// Cell provides the IdentityAllocator for allocating security identities
var Cell = cell.Module(
	"identity",
	"Allocating and managing security identities",

	cell.Provide(newIdentityAllocator),
)

// CachingIdentityAllocator provides an abstraction over the concrete type in
// pkg/identity/cache so that the underlying implementation can be mocked out
// in unit tests.
type CachingIdentityAllocator interface {
	cache.IdentityAllocator
	clustermesh.RemoteIdentityWatcher

	InitIdentityAllocator(versioned.Interface) <-chan struct{}

	// RestoreLocalIdentities reads in the checkpointed local allocator state
	// from disk and allocates a reference to every previously existing identity.
	//
	// Once all identity-allocating objects are synchronized (e.g. network policies,
	// remote nodes), call ReleaseRestoredIdentities to release the held references.
	RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error)

	// ReleaseRestoredIdentities releases any identities that were restored, reducing their reference
	// count and cleaning up as necessary.
	ReleaseRestoredIdentities()

	Close()
}

type identityAllocatorParams struct {
	cell.In

	Lifecycle        cell.Lifecycle
	PolicyRepository *policy.Repository
	PolicyUpdater    *policy.Updater
}

type identityAllocatorOut struct {
	cell.Out

	IdentityAllocator      CachingIdentityAllocator
	CacheIdentityAllocator cache.IdentityAllocator
	RemoteIdentityWatcher  clustermesh.RemoteIdentityWatcher
	IdentityObservable     stream.Observable[cache.IdentityChange]
}

func newIdentityAllocator(params identityAllocatorParams) identityAllocatorOut {
	// iao: updates SelectorCache and regenerates endpoints when
	// identity allocation / deallocation has occurred.
	iao := &identityAllocatorOwner{
		policy:        params.PolicyRepository,
		policyUpdater: params.PolicyUpdater,
	}

	// Allocator: allocates local and cluster-wide security identities.
	idAlloc := cache.NewCachingIdentityAllocator(iao)
	idAlloc.EnableCheckpointing()

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hc cell.HookContext) error {
			idAlloc.Close()
			return nil
		},
	})

	return identityAllocatorOut{
		IdentityAllocator:      idAlloc,
		CacheIdentityAllocator: idAlloc,
		RemoteIdentityWatcher:  idAlloc,
		IdentityObservable:     idAlloc,
	}
}

// identityAllocatorOwner is used to break the circular dependency between
// CachingIdentityAllocator and policy.Repository.
type identityAllocatorOwner struct {
	policy        *policy.Repository
	policyUpdater *policy.Updater
}

// UpdateIdentities informs the policy package of all identity changes
// and also triggers policy updates.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (iao *identityAllocatorOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
	wg := &sync.WaitGroup{}
	iao.policy.GetSelectorCache().UpdateIdentities(added, deleted, wg)
	// Wait for update propagation to endpoints before triggering policy updates
	wg.Wait()
	iao.policyUpdater.TriggerPolicyUpdates(false, "one or more identities created or deleted")
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (iao *identityAllocatorOwner) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4()
	case option.Config.EnableIPv6:
		ip = node.GetIPv6()
	}

	if ip == nil {
		log.Fatal("Node IP not available yet")
	}

	return ip.String()
}
