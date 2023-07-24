// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

package cmd

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/ipcache"

	"github.com/go-openapi/runtime/middleware"
)

type getIP struct{}

// NewGetIPHandler for the global IP cache
func NewGetIPHandler() GetIPHandler {
	return &getIP{}
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
	ipcache.IPIdentityCache.RLock()
	ipcache.IPIdentityCache.DumpToListenerLocked(listener)
	ipcache.IPIdentityCache.RUnlock()
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
	cidr net.IPNet, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity,
	newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
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
