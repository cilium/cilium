// Copyright 2018 Authors of Cilium
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
