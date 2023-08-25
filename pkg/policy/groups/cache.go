// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"sync"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var groupsCNPCache = groupsCNPCacheMap{}

type groupsCNPCacheMap struct {
	sync.Map
}

func (cnpCache *groupsCNPCacheMap) UpdateCNP(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.Store(cnp.ObjectMeta.UID, cnp)
}

func (cnpCache *groupsCNPCacheMap) DeleteCNP(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.Delete(cnp.ObjectMeta.UID)
}

func (cnpCache *groupsCNPCacheMap) GetAllCNP() []*cilium_v2.CiliumNetworkPolicy {
	result := []*cilium_v2.CiliumNetworkPolicy{}
	cnpCache.Range(func(k, v interface{}) bool {
		result = append(result, v.(*cilium_v2.CiliumNetworkPolicy))
		return true
	})
	return result
}
