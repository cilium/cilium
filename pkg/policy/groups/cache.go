// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"k8s.io/apimachinery/pkg/types"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
)

var groupsCNPCache = groupsCNPCacheMap{}

type groupsCNPCacheMap struct {
	lock.Map[types.UID, *cilium_v2.CiliumNetworkPolicy]
}

func (cnpCache *groupsCNPCacheMap) UpdateCNP(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.Store(cnp.ObjectMeta.UID, cnp)
}

func (cnpCache *groupsCNPCacheMap) DeleteCNP(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.Delete(cnp.ObjectMeta.UID)
}

func (cnpCache *groupsCNPCacheMap) GetAllCNP() []*cilium_v2.CiliumNetworkPolicy {
	result := []*cilium_v2.CiliumNetworkPolicy{}
	cnpCache.Range(func(_ types.UID, cnp *cilium_v2.CiliumNetworkPolicy) bool {
		result = append(result, cnp)
		return true
	})
	return result
}
