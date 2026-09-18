// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restoration

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
)

// Cell provides the LocalIdentityRestorer that is responsible to restore the local identities from
// the IPCache.
var Cell = cell.Module(
	"identity-restoration",
	"Restores local identities from the ipcache map at startup",

	cell.Provide(newLocalIdentityRestorer),
)

var (
	// the ipcache resource id (just a constant string) used for restored CIDRs
	restoredCIDRResource = ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "restored")
	ingressResource      = ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "ingress")
)

type localIdentityRestorerParams struct {
	cell.In

	Logger *slog.Logger

	// The global identity allocator is not yet initialized here at injection time
	// That happens in the daemon init via InitIdentityAllocator(). Only the local identity
	// allocator is initialized here.
	IdentityAllocator identitycell.CachingIdentityAllocator
	NodeLocalStore    *node.LocalNodeStore
}

type LocalIdentityRestorer struct {
	params localIdentityRestorerParams

	// CIDRs for which identities were restored during bootstrap
	restoredCIDRs map[netip.Prefix]identity.NumericIdentity
}

func newLocalIdentityRestorer(params localIdentityRestorerParams) *LocalIdentityRestorer {
	return &LocalIdentityRestorer{
		params:        params,
		restoredCIDRs: nil, // will be initialized during restoration
	}
}

// RestoreLocalIdentities restores the local identity state in the
// allocator and IPCache.
//
// First, the local identity allocator checkpoint is loaded.
// This will ensure that the same set of labels is assigned the same numeric
// identity once the agent has restored all state.
//
// Next, for any localPrefixes that mapped to a CIDR-specific identity in the
// outgoing ipcache bpf map, the ipcache metadata is re-created and inserted in
// to the ipcache.
//
// The purpose of this is to preserve stable local identities on agent
// restart as much as possible. This helps prevent spurious policy drops
// on agent restart.
//
// After a grace period, the restored identity references and placeholder ipcache
// metadata entries are removed, assuming that the agent has synchronized
// with other state (i.e. kvstore, k8s) and that all necessary entries
// are present in ipcache & the identity allocator.
//
// localPrefixes are read from the old ipcache map before it is recreated.
func (d *LocalIdentityRestorer) RestoreLocalIdentities(ipCache *ipcache.IPCache, localPrefixes map[netip.Prefix]identity.NumericIdentity) error {
	// Restore the local identity allocator from its checkpoint.
	// This returns the set of identities created. We will use this set
	// to regenerate the set of labels for prefixes in the ipcache.
	restoredIdentities, err := d.params.IdentityAllocator.RestoreLocalIdentities()

	// create placeholder CIDR labels in the ipcache.
	// This only adds an ipcache metadata entry for prefixes with a `cidr:`
	// label and ingress IPs. All other entries will have to be created anew.
	d.restoreIPCache(ipCache, localPrefixes, restoredIdentities)
	return err
}

// restoreIPCache recreated ipcache metadata entries from the dumped allocator and
// bpf map state.
//
// The goal of this logic is to ensure, as much as possible, that local identities (i.e. CIDR)
// get the same numeric identity upon agent restart.
//
// This reconstructs the ipcache state from the previous BPF map and the restored local
// identities. Specifically, if a prefix in the ipcache has a CIDR label, this re-creates
// that metadata entry.
//
// For ingress IPs, it adds them to the ipcache and overwrites any addresses
// restored from Kubernetes on the local node. The BPF map reflects the
// addresses used by the previous datapath and therefore has highest restoration
// precedence.
func (d *LocalIdentityRestorer) restoreIPCache(ipCache *ipcache.IPCache, localPrefixes map[netip.Prefix]identity.NumericIdentity, restoredIdentities map[identity.NumericIdentity]*identity.Identity) {
	if len(localPrefixes) == 0 {
		return
	}

	metaUpdates := make([]ipcache.MU, 0, len(localPrefixes))
	d.restoredCIDRs = make(map[netip.Prefix]identity.NumericIdentity, len(localPrefixes))
	nidsToWithhold := []identity.NumericIdentity{}

	// Determine which numeric identities are not shared.
	// This is used for identity recreation.
	uniqueIDs := map[identity.NumericIdentity]struct{}{}
	sharedIDs := map[identity.NumericIdentity]struct{}{}
	for _, nid := range localPrefixes {
		if _, ok := sharedIDs[nid]; ok {
			continue
		} else if _, ok := uniqueIDs[nid]; ok {
			delete(uniqueIDs, nid)
			sharedIDs[nid] = struct{}{}
			continue
		} else {
			uniqueIDs[nid] = struct{}{}
		}
	}

	// Loop through prefixes recovered from the ipcache, using a few different
	// heuristics to recreate the metadata in the ipcache.
	for prefix, nid := range localPrefixes {
		// Restore Ingress IPs as necessary
		if nid == identity.ReservedIdentityIngress {
			metaUpdates = append(metaUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
				Source:   source.Restored,
				Resource: ingressResource,
				Metadata: []ipcache.IPMetadata{labels.LabelIngress},
			})

			// BPF ipcache state takes precedence over the Kubernetes Node and
			// CiliumNode fallbacks restored on the local node earlier.
			d.params.NodeLocalStore.Update(func(n *node.LocalNode) {
				addr := prefix.Addr()
				if addr.Is4() {
					n.IPv4IngressIP = iputil.AddrFrom(addr)
				} else {
					n.IPv6IngressIP = iputil.AddrFrom(addr)
				}
			})
			d.params.Logger.Info("Restored ingress IP", logfields.Ingress, prefix)
			continue
		}

		// For every prefix -> nid pair, look to see if there is a restored identity for this nid.
		// If not, then request the same numeric identity *and* possibly insert CIDR labels
		// If yes, **and** the identity contains the prefix `cidr:` label,
		//   then upsert that exact set of labels in the ipcache.
		id := restoredIdentities[nid]
		if id == nil {
			// Always request the previous numeric ID for this prefix.
			metadata := []ipcache.IPMetadata{ipcachetypes.RequestedIdentity(nid)}

			// If this numeric ID is not shared by any other prefixes, add CIDR labels
			// as well.
			if _, unique := uniqueIDs[nid]; unique {
				metadata = append(metadata, labels.GetCIDRLabels(prefix))
			}

			// Commit to ipcache.
			metaUpdates = append(metaUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
				Source:   source.Restored,
				Resource: restoredCIDRResource,
				Metadata: metadata,
			})
			d.restoredCIDRs[prefix] = nid
			nidsToWithhold = append(nidsToWithhold, nid)
			d.params.Logger.Debug("ipache prefix not found in allocator cache, requesting identity", logfields.Prefix, prefix)

		} else {
			// The prefix's labels *have* been restored from the checkpoint.
			//
			// This is needed in particular for CIDR identities and
			// FQDN identities, as they are derived from policies and thus are
			// not available before endpoint regeneration starts, but need to
			// be present in the new IPCache during endpoint regeneration to
			// avoid drops.
			metaUpdates = append(metaUpdates, ipcache.MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
				Source:   source.Restored,
				Resource: restoredCIDRResource,
				Metadata: []ipcache.IPMetadata{id.Labels},
			})
			d.params.Logger.Debug("restoring local ipcache entry",
				logfields.Labels, id.Labels,
				logfields.Prefix, prefix,
			)

			d.restoredCIDRs[prefix] = nid
		}
	}

	// Insert the batched changes in to the ipcache.
	// Even though the ipcache map hasn't been initialized yet, this is
	// safe to do so, because the ipcache's apply controller is currently
	// paused.
	ipCache.IdentityAllocator.WithholdLocalIdentities(nidsToWithhold)
	ipCache.UpsertMetadataBatch(metaUpdates...)

	d.params.Logger.Info("restored prefixes in the ipcache",
		logfields.Count, len(d.restoredCIDRs),
		logfields.Total, len(localPrefixes),
	)
}

// ReleaseRestoredIdentities removes the placeholder state that was inserted
// in to the ipcache and local identity allocators on restoration
//
// Any identities and prefixes actually in use will still exist after this.
//
// This should be called after a grace period (default 30 seconds,
// 10 minutes for kvstore, set by --identity-restore-grace-period).
// This grace period is needed when running on an external workload
// where policy synchronization is not done via k8s. Also in k8s
// case it is prudent to allow concurrent endpoint regenerations to
// (re-)allocate the restored identities before we release them.
//
// Any CIDRs still in use after the grace period will have other sources
// of metadata in the ipcache, and thus will remain. CIDRs for which
// restoration was the only source of metadata will be deallocated. Identities
// with no references after restoration will be deallocated.
func (d *LocalIdentityRestorer) ReleaseRestoredIdentities(ipCache *ipcache.IPCache) {
	defer func() {
		// release the memory held by restored CIDRs
		d.restoredCIDRs = nil
	}()

	// Remove any references to restored identities in the local allocators
	d.params.IdentityAllocator.ReleaseRestoredIdentities()

	if len(d.restoredCIDRs) == 0 {
		return
	}

	d.params.Logger.Info("Removing identity reservations for restored identities", logfields.Count, len(d.restoredCIDRs))
	updates := make([]ipcache.MU, 0, len(d.restoredCIDRs))
	nids := make([]identity.NumericIdentity, 0, len(d.restoredCIDRs))
	for prefix, nid := range d.restoredCIDRs {
		nids = append(nids, nid)
		updates = append(updates, ipcache.MU{
			Prefix:   cmtypes.NewLocalPrefixCluster(prefix),
			Resource: restoredCIDRResource,
			Metadata: []ipcache.IPMetadata{
				ipcachetypes.RequestedIdentity(0), // remove requested ID, if present
				labels.Labels{},                   // remove labels, if present
			},
		})
	}

	ipCache.RemoveMetadataBatch(updates...)
	ipCache.IdentityAllocator.UnwithholdLocalIdentities(nids)
}
