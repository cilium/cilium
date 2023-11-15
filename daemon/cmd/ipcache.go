// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	// the ipcache resource id (just a constant string) used for restored CIDRs
	restoredCIDRResource = ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "restored")
	ingressResource      = ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "ingress")
)

func getIPHandler(d *Daemon, params GetIPParams) middleware.Responder {
	listener := &ipCacheDumpListener{}
	if params.Cidr != nil {
		_, cidrFilter, err := net.ParseCIDR(*params.Cidr)
		if err != nil {
			return api.Error(GetIPBadRequestCode, err)
		}
		listener.cidrFilter = cidrFilter
	}
	d.ipcache.DumpToListener(listener)
	if len(listener.entries) == 0 {
		return NewGetIPNotFound()
	}

	return NewGetIPOK().WithPayload(listener.entries)
}

type ipCacheDumpListener struct {
	cidrFilter *net.IPNet
	entries    []*models.IPListEntry
}

// OnIPIdentityCacheChange is called by DumpToListenerLocked
func (ipc *ipCacheDumpListener) OnIPIdentityCacheChange(modType ipcache.CacheModification,
	cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity,
	newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	cidr := cidrCluster.AsIPNet()

	// only capture entries which are a subnet of cidrFilter
	if ipc.cidrFilter != nil && !containsSubnet(*ipc.cidrFilter, cidr) {
		return
	}

	cidrStr := cidr.String()
	identity := int64(newID.ID.Uint32())
	hostIP := ""
	if newHostIP != nil {
		hostIP = newHostIP.String()
	}

	entry := &models.IPListEntry{
		Cidr:       &cidrStr,
		Identity:   &identity,
		HostIP:     hostIP,
		EncryptKey: int64(encryptKey),
	}

	if k8sMeta != nil {
		entry.Metadata = &models.IPListEntryMetadata{
			Source:    string(newID.Source),
			Namespace: k8sMeta.Namespace,
			Name:      k8sMeta.PodName,
			// TODO (jrajahalme): Consider if named ports should be
			//                    made visible in the model.
		}
	}

	ipc.entries = append(ipc.entries, entry)
}

// containsSubnet returns true if 'outer' contains 'inner'
func containsSubnet(outer, inner net.IPNet) bool {
	outerOnes, outerBits := outer.Mask.Size()
	innerOnes, innerBits := inner.Mask.Size()

	return outerBits == innerBits && outerOnes <= innerOnes && outer.Contains(inner.IP)
}

// restoreIPCache dumps the existing (old) bpf ipcache, adding relevant information
// back in to the ipcache / identity allocator.
//
// The goal of this logic is to ensure, as much as possible, that local identities (i.e. CIDR)
// get the same numeric identity upon agent restart.
//
// For all local (cidr / remote-node) identities found, this adds a placeholder entry in the
// ipcache metadata layer requesting the previous numeric identity. When the agent initializes
// and the ipcache finally recreates the bpf map, this placeholder entry ensures the prefixes
// exist and have the same identity as before.
//
// After a grace period, the placeholder metadata is removed and any prefixes not referenced
// by other subsystems will be deallocated, see releaseRestoredCIDRs().
// (Aside: prefix references mostly come from network policies, either directly through CIDR
// selectors or via ToFQDN rules.)
//
// For ingress IPs, it will add those to the ipcache and configure the local node
// accordingly.
//
// This *must* be called before initMaps(), which will hide the "old" ipcache.
func (d *Daemon) restoreIPCache() error {
	ingressIPs := make([]netip.Prefix, 0, 2)
	// need to preserve this so we can remove it later.
	d.restoredCIDRs = map[netip.Prefix]identity.NumericIdentity{}

	// Dump the bpf ipcache, recording any prefixes with local or ingress
	// numeric identities.
	err := ipcachemap.IPCacheMap().DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		k := key.(*ipcachemap.Key)
		v := value.(*ipcachemap.RemoteEndpointInfo)
		nid := identity.NumericIdentity(v.SecurityIdentity)

		if isLocalIdentity(nid) {
			d.restoredCIDRs[k.Prefix()] = nid
		} else if nid == identity.ReservedIdentityIngress && v.TunnelEndpoint.IsZero() {
			ingressIPs = append(ingressIPs, k.Prefix())
		}
	})
	// dumpwithcallback() leaves the ipcache map open, must close before opened for
	// parallel mode in daemon.initmaps()
	ipcachemap.IPCacheMap().Close()

	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("error dumping ipcache: %w", err)
	}

	// Now that the map is dumped,
	// - upsert relevant metadata in to the ipcache
	// - withhold all existing CIDR identities
	// - add Ingress IPs to local Node.
	metaUpdates := make([]ipcache.MU, 0, len(ingressIPs)+len(d.restoredCIDRs))
	nidsToWithhold := make([]identity.NumericIdentity, 0, len(d.restoredCIDRs))

	for prefix, nid := range d.restoredCIDRs {
		nidsToWithhold = append(nidsToWithhold, nid)
		metaUpdates = append(metaUpdates, ipcache.MU{
			Prefix:   prefix,
			Source:   source.Restored,
			Resource: restoredCIDRResource,
			Metadata: []ipcache.IPMetadata{ipcachetypes.RequestedIdentity(nid)},
		})
	}
	for _, prefix := range ingressIPs {
		metaUpdates = append(metaUpdates, ipcache.MU{
			Prefix:   prefix,
			Source:   source.Restored,
			Resource: ingressResource,
			Metadata: []ipcache.IPMetadata{labels.LabelIngress},
		})

		// Set any restored ingress IPs back on the LocalNode object
		d.nodeLocalStore.Update(func(n *node.LocalNode) {
			addr := prefix.Addr()
			if addr.Is4() {
				n.IPv4IngressIP = addr.AsSlice()
			} else {
				n.IPv6IngressIP = addr.AsSlice()
			}
		})
	}
	if len(ingressIPs) > 0 {
		log.WithField(logfields.Ingress, ingressIPs).Info("Restored ingress IPs")
	}

	// Insert the batched changes in to the ipcache.
	// Even though the ipcache map hasn't been initialized yet, this is
	// safe to do so, because the ipcache's apply controller is currently
	// paused.
	d.ipcache.IdentityAllocator.WithholdLocalIdentities(nidsToWithhold)
	d.ipcache.UpsertMetadataBatch(metaUpdates...)

	return nil
}

// releaseRestoredCIDRS removes the placeholder metadata that was inserted
// in to the ipcache when local identities were restored.
// Any identities actually in use will still exist after this.
//
// This should be called after a grace period (default 10 minutes, set
// by --identity-restore-grace-period).
// This grace period is needed when running on an external workload
// where policy synchronization is not done via k8s. Also in k8s
// case it is prudent to allow concurrent endpoint regenerations to
// (re-)allocate the restored identities before we release them.
//
// Any CIDRs still in use after the grace period will have other sources
// of metadata in the ipcache, and thus will remain. CIDRs for which
// restoration was the only source of metadata will be deallocated.
func (d *Daemon) releaseRestoredCIDRs() {
	defer func() {
		// release the memory held by restored CIDRs
		d.restoredCIDRs = nil
	}()
	if len(d.restoredCIDRs) == 0 {
		return
	}

	log.WithField(logfields.Count, len(d.restoredCIDRs)).Info("Removing identity reservations for restored CIDR identities")
	updates := make([]ipcache.MU, 0, len(d.restoredCIDRs))
	nids := make([]identity.NumericIdentity, 0, len(d.restoredCIDRs))
	for prefix, nid := range d.restoredCIDRs {
		nids = append(nids, nid)
		updates = append(updates, ipcache.MU{
			Prefix:   prefix,
			Resource: restoredCIDRResource,
			Metadata: []ipcache.IPMetadata{ipcachetypes.RequestedIdentity(0)},
		})
	}

	d.ipcache.RemoveMetadataBatch(updates...)
	d.ipcache.IdentityAllocator.UnwithholdLocalIdentities(nids)
}

func isLocalIdentity(nid identity.NumericIdentity) bool {
	scope := nid.Scope()
	return scope == identity.IdentityScopeLocal ||
		(scope == identity.IdentityScopeRemoteNode && option.Config.PolicyCIDRMatchesNodes())
}
