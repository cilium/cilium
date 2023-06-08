// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

// A "dummy" set of per-cluster CT maps for testing. It implements PerClusterCTMapper.
type dummyPerClusterCTMaps struct {
	lock.RWMutex
	ipv4 bool
	ipv6 bool
	tcp4 map[uint32]struct{}
	any4 map[uint32]struct{}
	tcp6 map[uint32]struct{}
	any6 map[uint32]struct{}
}

// Init a "dummy" global per-cluster CT maps
func InitDummyPerClusterCTMaps(ipv4, ipv6 bool) {
	PerClusterCTMaps = newDummyPerClusterCTMaps(ipv4, ipv6)
}

func newDummyPerClusterCTMaps(ipv4, ipv6 bool) *dummyPerClusterCTMaps {
	gm := &dummyPerClusterCTMaps{
		ipv4: ipv4,
		ipv6: ipv6,
	}

	if ipv4 {
		gm.tcp4 = make(map[uint32]struct{})
		gm.any4 = make(map[uint32]struct{})
	}

	if ipv6 {
		gm.tcp6 = make(map[uint32]struct{})
		gm.any6 = make(map[uint32]struct{})
	}

	return gm
}

func (gm *dummyPerClusterCTMaps) UpdateClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		gm.tcp4[clusterID] = struct{}{}
		gm.any4[clusterID] = struct{}{}
	}

	if gm.ipv6 {
		gm.tcp6[clusterID] = struct{}{}
		gm.any6[clusterID] = struct{}{}
	}

	return nil
}

func (gm *dummyPerClusterCTMaps) DeleteClusterCTMaps(clusterID uint32) error {
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return err
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		delete(gm.tcp4, clusterID)
		delete(gm.any4, clusterID)
	}

	if gm.ipv6 {
		delete(gm.tcp6, clusterID)
		delete(gm.any6, clusterID)
	}

	return nil
}

func (gm *dummyPerClusterCTMaps) GetClusterCTMaps(clusterID uint32) []*Map {
	ims := []*Map{}

	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return []*Map{}
	}

	gm.Lock()
	defer gm.Unlock()

	if gm.ipv4 {
		if _, ok := gm.tcp4[clusterID]; ok {
			ims = append(ims, &Map{})
		}
		if _, ok := gm.any4[clusterID]; ok {
			ims = append(ims, &Map{})
		}
	}

	if gm.ipv6 {
		if _, ok := gm.tcp6[clusterID]; ok {
			ims = append(ims, &Map{})
		}
		if _, ok := gm.any6[clusterID]; ok {
			ims = append(ims, &Map{})
		}
	}

	return ims
}

func (gm *dummyPerClusterCTMaps) GetAllClusterCTMaps() ([]*Map, error) {
	ims := []*Map{}

	gm.RLock()
	defer gm.RUnlock()

	for i := uint32(1); i <= cmtypes.ClusterIDMax; i++ {
		if gm.ipv4 {
			if _, ok := gm.tcp4[i]; ok {
				ims = append(ims, &Map{})
			}
			if _, ok := gm.any4[i]; ok {
				ims = append(ims, &Map{})
			}
		}
		if gm.ipv6 {
			if _, ok := gm.tcp6[i]; ok {
				ims = append(ims, &Map{})
			}
			if _, ok := gm.any6[i]; ok {
				ims = append(ims, &Map{})
			}
		}
	}

	return ims, nil
}

func (gm *dummyPerClusterCTMaps) Cleanup() {
	gm.RLock()
	defer gm.RUnlock()

	if gm.ipv4 {
		gm.tcp4 = nil
		gm.any4 = nil
	}

	if gm.ipv6 {
		gm.tcp6 = nil
		gm.any6 = nil
	}

	return
}
