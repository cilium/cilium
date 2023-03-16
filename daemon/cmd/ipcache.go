// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"net/netip"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathIPCache "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/source"
)

type initializerParams struct {
	cell.In

	Lifecycle       hive.Lifecycle
	AgentIPCache    *ipcache.IPCache
	DatapathIPCache datapathIPCache.BPFListenerInterface
	LocalNodeStore  node.LocalNodeStore
}

type IPCacheInitializer struct{}

func newIPCacheInitializer(params initializerParams) *IPCacheInitializer {
	params.Lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			oldIngressIPs := params.DatapathIPCache.GetOldIngressIPs()
			restoredCIDRs := params.DatapathIPCache.GetOldCIDRs()
			oldNIDs := params.DatapathIPCache.GetOldNIDs()

			for _, ingressIP := range oldIngressIPs {
				ip := ingressIP.IP
				if ip.To4() != nil {
					params.LocalNodeStore.Update(func(n *node.LocalNode) {
						n.IPv4IngressIP = ip
					})
				} else {
					params.LocalNodeStore.Update(func(n *node.LocalNode) {
						n.IPv6IngressIP = ip
					})
				}
			}

			// Preallocate IDs for old CIDRs. This must be done before any Identity allocations are
			// possible so that the old IDs are still available. That is why we do this ASAP after the
			// new (userspace) ipcache is created above.
			//
			// CIDRs were dumped from the old ipcache, they are re-allocated here, hopefully with the
			// same numeric IDs as before, but the restored identities are to be upsterted to the new
			// (datapath) ipcache after it has been initialized below. This is accomplished by passing
			// 'restoredCIDRidentities' to AllocateCIDRs() and then calling
			// UpsertGeneratedIdentities(restoredCIDRidentities) after initMaps() below.
			restoredCIDRidentities := make(map[netip.Prefix]*identity.Identity)
			if len(restoredCIDRs) > 0 {
				log.Infof("Restoring %d old CIDR identities", len(restoredCIDRs))
				_, err := params.AgentIPCache.AllocateCIDRs(restoredCIDRs, oldNIDs, restoredCIDRidentities)
				if err != nil {
					log.WithError(err).Error("Error allocating old CIDR identities")
				}
				// Log a warning for the first CIDR identity than could not be restored with the
				// same numeric identity as before the restart. This can only happen if we have
				// re-introduced bugs into this agent bootstrap order, so we want to surface this.
				for i, prefix := range restoredCIDRs {
					id, exists := restoredCIDRidentities[prefix]
					if !exists || id.ID != oldNIDs[i] {
						log.WithField(logfields.Identity, oldNIDs[i]).Warn("Could not restore all CIDR identities")
						break
					}
				}
			}

			// Set up the list of IPCache listeners in the daemon, to be
			// used by syncEndpointsAndHostIPs()
			// xDS cache will be added later by calling AddListener(), but only if necessary.
			params.AgentIPCache.SetListeners([]ipcache.IPIdentityMappingListener{
				params.DatapathIPCache,
			})

			// Upsert restored CIDRs after the new ipcache has been opened above
			if len(restoredCIDRidentities) > 0 {
				params.AgentIPCache.UpsertGeneratedIdentities(restoredCIDRidentities, nil)
			}
			// Upsert restored local Ingress IPs
			restoredIngressIPs := []string{}
			for _, ingressIP := range oldIngressIPs {
				_, err := params.AgentIPCache.Upsert(ingressIP.String(), nil, 0, nil, ipcache.Identity{
					ID:     identity.ReservedIdentityIngress,
					Source: source.Restored,
				})
				if err == nil {
					restoredIngressIPs = append(restoredIngressIPs, ingressIP.String())
				} else {
					log.WithError(err).Warning("could not restore Ingress IP, a new one will be allocated")
				}
			}
			if len(restoredIngressIPs) > 0 {
				log.WithField(logfields.Ingress, restoredIngressIPs).Info("Restored ingress IPs")
			}

			return nil
		},
	})

	return &IPCacheInitializer{}
}

type getIP struct {
	d *Daemon
}

// NewGetIPHandler for the global IP cache
func NewGetIPHandler(d *Daemon) GetIPHandler {
	return &getIP{d: d}
}

func (h *getIP) Handle(params GetIPParams) middleware.Responder {
	listener := &ipCacheDumpListener{}
	if params.Cidr != nil {
		_, cidrFilter, err := net.ParseCIDR(*params.Cidr)
		if err != nil {
			return api.Error(GetIPBadRequestCode, err)
		}
		listener.cidrFilter = cidrFilter
	}
	h.d.ipcache.DumpToListener(listener)
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
	newID ipcache.Identity, encryptKey uint8, _ uint16, k8sMeta *ipcache.K8sMetadata) {
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

// OnIPIdentityCacheGC is required to implement IPIdentityMappingListener.
func (ipc *ipCacheDumpListener) OnIPIdentityCacheGC() {
	// Nothing to do.
}

// containsSubnet returns true if 'outer' contains 'inner'
func containsSubnet(outer, inner net.IPNet) bool {
	outerOnes, outerBits := outer.Mask.Size()
	innerOnes, innerBits := inner.Mask.Size()

	return outerBits == innerBits && outerOnes <= innerOnes && outer.Contains(inner.IP)
}
