// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"

	"github.com/go-openapi/runtime/middleware"
)

type getIPCache struct{}

// NewGetIPCacheHandler for the global IP cache
func NewGetIPCacheHandler() GetIPCacheHandler {
	return &getIPCache{}
}

func (h *getIPCache) Handle(params GetIPCacheParams) middleware.Responder {
	listener := &ipCacheDumpListener{}
	if params.Cidr != nil {
		_, cidrFilter, err := net.ParseCIDR(*params.Cidr)
		if err != nil {
			return api.Error(GetIPCacheBadRequestCode, err)
		}
		listener.cidrFilter = cidrFilter
	}
	ipcache.IPIdentityCache.RLock()
	ipcache.IPIdentityCache.DumpToListenerLocked(listener)
	ipcache.IPIdentityCache.RUnlock()
	if len(listener.entries) == 0 {
		return NewGetIPCacheNotFound()
	}

	return NewGetIPCacheOK().WithPayload(&models.IPCache{
		Cache: listener.entries,
	})
}

type ipCacheDumpListener struct {
	cidrFilter *net.IPNet
	entries    []*models.IPCacheEntry
}

// OnIPIdentityCacheChange is called by DumpToListenerLocked
func (ipc *ipCacheDumpListener) OnIPIdentityCacheChange(modType ipcache.CacheModification,
	cidr net.IPNet, oldHostIP, newHostIP net.IP, oldID *identity.NumericIdentity,
	newID identity.NumericIdentity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	// only capture entries which are a subnet of cidrFilter
	if ipc.cidrFilter != nil && !containsSubnet(*ipc.cidrFilter, cidr) {
		return
	}

	cidrStr := cidr.String()
	identity := int64(newID.Uint32())
	hostIP := ""
	if newHostIP != nil {
		hostIP = newHostIP.String()
	}

	entry := &models.IPCacheEntry{
		Cidr:       &cidrStr,
		Identity:   &identity,
		HostIP:     hostIP,
		EncryptKey: int64(encryptKey),
	}

	if k8sMeta != nil {
		entry.K8sMetadata = &models.IPCacheEntryK8sMetadata{
			Namespace: k8sMeta.Namespace,
			PodName:   k8sMeta.PodName,
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
