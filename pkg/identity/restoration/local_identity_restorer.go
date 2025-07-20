// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restoration

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
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
	IPCache           *ipcache.IPCache
	NodeLocalStore    *node.LocalNodeStore
	MetricsRegistry   *metrics.Registry
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
// Next, the outgoing ipcache bpf map is read. For any prefixes that
// mapped to a CIDR-specific identity, the ipcache metadata is re-created
// and inserted in to the ipcache.
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
// This *must* be called before initMaps(), which will hide the "old" ipcache.
func (d *LocalIdentityRestorer) RestoreLocalIdentities() error {
	// Restore the local identity allocator from its checkpoint.
	// This returns the set of identities created. We will use this set
	// to regenerate the set of labels for prefixes in the ipcache.
	restoredIdentities, err := d.params.IdentityAllocator.RestoreLocalIdentities()

	// Dump the existing BPF ipcache map
	localPrefixes, err2 := d.dumpOldIPCache()
	if err2 != nil {
		d.params.Logger.Warn("Failed to restore existing identities from the previous ipcache. This may cause policy interruptions during restart.", logfields.Error, err2)
		err = errors.Join(err, err2)
		// continue; we may have a partial dump
	}

	// create placeholder CIDR labels in the ipcache.
	// This only adds an ipcache metadata entry for prefixes with a `cidr:`
	// label and ingress IPs. All other entries will have to be created anew.
	d.restoreIPCache(localPrefixes, restoredIdentities)
	return err
}

// dumpOldIPCache reads the soon-to-be-overwritten ipcache BPF map, noting any prefixes
// with a locally-scoped or ingress identity.
func (d *LocalIdentityRestorer) dumpOldIPCache() (map[netip.Prefix]identity.NumericIdentity, error) {
	localPrefixes := map[netip.Prefix]identity.NumericIdentity{}

	// Dump the bpf ipcache, recording any prefixes with local or ingress
	// numeric identities.
	err := ipcachemap.IPCacheMap(d.params.MetricsRegistry).DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*ipcachemap.Key)
		v := value.(*ipcachemap.RemoteEndpointInfo)
		nid := identity.NumericIdentity(v.SecurityIdentity)

		if !v.TunnelEndpoint.IsZero() || k.ClusterID != 0 {
			return
		}

		if nid.Scope() == identity.IdentityScopeLocal || nid == identity.ReservedIdentityIngress {
			localPrefixes[k.Prefix()] = nid
		}
	})
	// dumpwithcallback() leaves the ipcache map open, must close before opened for
	// parallel mode in daemon.initmaps()
	ipcachemap.IPCacheMap(d.params.MetricsRegistry).Close()

	if err != nil {
		// ignore non-existent cache
		if errors.Is(err, fs.ErrNotExist) {
			// We might be in the upgrade case, with the ipcache v1 from v1.18
			// still around.
			return d.dumpOldIPCacheV1()
		}
	}
	d.params.Logger.Debug("dumping ipache with local identities", logfields.Count, len(localPrefixes))
	return localPrefixes, err
}

// dumpOldIPCacheV1 does the same as dumpOldIPCache but for the v1 of the ipcache map.
func (d *LocalIdentityRestorer) dumpOldIPCacheV1() (map[netip.Prefix]identity.NumericIdentity, error) {
	localPrefixes := map[netip.Prefix]identity.NumericIdentity{}

	// Dump the bpf ipcache, recording any prefixes with local or ingress
	// numeric identities.
	err := ipcachemap.IPCacheMapV1().DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*ipcachemap.Key)
		v := value.(*ipcachemap.RemoteEndpointInfoV1)
		nid := identity.NumericIdentity(v.SecurityIdentity)

		if nid.Scope() == identity.IdentityScopeLocal || (nid == identity.ReservedIdentityIngress && v.TunnelEndpoint.IsZero()) {
			localPrefixes[k.Prefix()] = nid
		}
	})
	// dumpwithcallback() leaves the ipcache map open, must close before opened for
	// parallel mode in daemon.initmaps()
	ipcachemap.IPCacheMapV1().Close()

	if err != nil {
		// ignore non-existent cache
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
	}
	d.params.Logger.Debug("dumping ipache with local identities", logfields.Count, len(localPrefixes))
	return localPrefixes, err
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
// For ingress IPs, it will add those to the ipcache and configure the local node
// accordingly.
func (d *LocalIdentityRestorer) restoreIPCache(localPrefixes map[netip.Prefix]identity.NumericIdentity, restoredIdentities map[identity.NumericIdentity]*identity.Identity) {
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

			// Set any restored ingress IPs back on the LocalNode object
			d.params.NodeLocalStore.Update(func(n *node.LocalNode) {
				addr := prefix.Addr()
				if addr.Is4() {
					n.IPv4IngressIP = addr.AsSlice()
				} else {
					n.IPv6IngressIP = addr.AsSlice()
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
	d.params.IPCache.IdentityAllocator.WithholdLocalIdentities(nidsToWithhold)
	d.params.IPCache.UpsertMetadataBatch(metaUpdates...)

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
func (d *LocalIdentityRestorer) ReleaseRestoredIdentities() {
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

	d.params.IPCache.RemoveMetadataBatch(updates...)
	d.params.IPCache.IdentityAllocator.UnwithholdLocalIdentities(nids)
}
