// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"iter"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type poolStore map[string]*LBPool

func newPoolStore() poolStore {
	return make(map[string]*LBPool)
}

func (ps poolStore) Ranges() iter.Seq[*LBRange] {
	return func(yield func(*LBRange) bool) {
		for _, pool := range ps {
			for _, lbRange := range pool.ranges {
				if !yield(lbRange) {
					return
				}
			}
		}
	}
}

type LBPool struct {
	k8s    *cilium_api_v2.CiliumLoadBalancerIPPool
	ranges []*LBRange
}

func (p *LBPool) GetName() string {
	return p.k8s.Name
}
