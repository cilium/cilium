// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// poolStore is a storage structure for IPPools
type poolStore struct {
	// Map of all IP pools
	pools map[string]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool
}

func NewPoolStore() poolStore {
	return poolStore{
		pools: make(map[string]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool),
	}
}

func (ps *poolStore) Upsert(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	if pool == nil {
		return
	}
	ps.pools[pool.GetName()] = pool
}

func (ps *poolStore) Delete(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	delete(ps.pools, pool.GetName())
}

func (ps *poolStore) GetByName(name string) (*cilium_api_v2alpha1.CiliumLoadBalancerIPPool, bool) {
	pool, found := ps.pools[name]
	return pool, found
}
