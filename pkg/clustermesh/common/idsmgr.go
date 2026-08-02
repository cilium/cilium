// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

// ClusterIDsManager reserves remote cluster IDs to ensure their uniqueness.
type ClusterIDsManager interface {
	ReserveClusterID(clusterID uint32) error
	ReleaseClusterID(clusterID uint32)
}

type clusterIDsManager struct {
	localClusterID uint32
	usedIDs        sets.Set[uint32]
	mutex          lock.RWMutex
}

// NewClusterIDsManager constructs a manager for remote cluster IDs.
func NewClusterIDsManager(info types.ClusterInfo) ClusterIDsManager {
	return &clusterIDsManager{
		localClusterID: info.ID,
		usedIDs:        sets.New[uint32](),
	}
}

func (m *clusterIDsManager) ReserveClusterID(clusterID uint32) error {
	if clusterID == types.ClusterIDUnset {
		return fmt.Errorf("clusterID %d is reserved", clusterID)
	}
	if clusterID == m.localClusterID {
		return fmt.Errorf("clusterID %d is assigned to the local cluster", clusterID)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.usedIDs.Has(clusterID) {
		return fmt.Errorf("clusterID %d is already used", clusterID)
	}
	m.usedIDs.Insert(clusterID)
	return nil
}

func (m *clusterIDsManager) ReleaseClusterID(clusterID uint32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.usedIDs.Delete(clusterID)
}
