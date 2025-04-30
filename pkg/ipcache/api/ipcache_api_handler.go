// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	policyapi "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
)

type IPCacheGetIPHandler struct {
	ipcache           *ipcache.IPCache
	identityAllocator identitycell.CachingIdentityAllocator
}

func NewIPCacheGetIPHandler(ipcache *ipcache.IPCache, identityAllocator identitycell.CachingIdentityAllocator) *IPCacheGetIPHandler {
	return &IPCacheGetIPHandler{
		ipcache:           ipcache,
		identityAllocator: identityAllocator,
	}
}

func (r *IPCacheGetIPHandler) Handle(params policyapi.GetIPParams) middleware.Responder {
	listener := &ipCacheDumpListener{
		identityAllocator: r.identityAllocator,
	}
	if params.Cidr != nil {
		_, cidrFilter, err := net.ParseCIDR(*params.Cidr)
		if err != nil {
			return api.Error(policyapi.GetIPBadRequestCode, err)
		}
		listener.cidrFilter = cidrFilter
	}
	if params.Labels != nil {
		listener.labelsFilter = labels.NewLabelsFromModel(params.Labels)
	}
	r.ipcache.DumpToListener(listener)
	if len(listener.entries) == 0 {
		return policyapi.NewGetIPNotFound()
	}

	return policyapi.NewGetIPOK().WithPayload(listener.entries)
}

type ipCacheDumpListener struct {
	cidrFilter        *net.IPNet
	labelsFilter      labels.Labels
	identityAllocator identitycell.CachingIdentityAllocator
	entries           []*models.IPListEntry
}

// getIdentity implements IdentityGetter. It looks up identity by ID from
// Cilium's identity cache.
func (ipc *ipCacheDumpListener) getIdentity(securityIdentity uint32) (*identity.Identity, error) {
	ident := ipc.identityAllocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident, nil
}

// OnIPIdentityCacheChange is called by DumpToListenerLocked
func (ipc *ipCacheDumpListener) OnIPIdentityCacheChange(modType ipcache.CacheModification,
	cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity,
	newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8,
) {
	cidr := cidrCluster.AsIPNet()

	// only capture entries which are a subnet of cidrFilter
	if ipc.cidrFilter != nil && !containsSubnet(*ipc.cidrFilter, cidr) {
		return
	}
	// Only capture identities with requested labels
	if ipc.labelsFilter != nil {
		id, err := ipc.getIdentity(newID.ID.Uint32())
		if err != nil {
			return
		}
		for _, label := range ipc.labelsFilter {
			if !id.Labels.Has(label) {
				return
			}
		}
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
