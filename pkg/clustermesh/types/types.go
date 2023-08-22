// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"

	"github.com/cilium/cilium/pkg/defaults"
)

const (
	// ClusterIDMin is the minimum value of the cluster ID
	ClusterIDMin    = 0
	ClusterIDExt511 = 511
)

// ClusterIDMax is the maximum value of the cluster ID
var ClusterIDMax uint32 = defaults.MaxConnectedClusters

// InitClusterIDMax validates and sets the ClusterIDMax package level variable.
func (c ClusterInfo) InitClusterIDMax() error {
	switch c.MaxConnectedClusters {
	case defaults.MaxConnectedClusters, ClusterIDExt511:
		ClusterIDMax = c.MaxConnectedClusters
	default:
		return fmt.Errorf("--%s=%d is invalid; supported values are [%d, %d]", OptMaxConnectedClusters, c.MaxConnectedClusters, defaults.MaxConnectedClusters, ClusterIDExt511)
	}
	return nil
}

// ValidateClusterID ensures that the given clusterID is within the configured
// range of the ClusterMesh.
func ValidateClusterID(clusterID uint32) error {
	if clusterID == ClusterIDMin {
		return fmt.Errorf("ClusterID %d is reserved", ClusterIDMin)
	}

	if clusterID > ClusterIDMax {
		return fmt.Errorf("ClusterID > %d is not supported", ClusterIDMax)
	}

	return nil
}

type CiliumClusterConfig struct {
	ID uint32 `json:"id,omitempty"`

	Capabilities CiliumClusterConfigCapabilities `json:"capabilities,omitempty"`
}

type CiliumClusterConfigCapabilities struct {
	// Supports per-prefix "synced" canaries
	SyncedCanaries bool `json:"syncedCanaries,omitempty"`

	// The information concerning the given cluster is cached from an external
	// kvstore (for instance, by kvstoremesh). This implies that keys are stored
	// under the dedicated "cilium/cache" prefix, and all are cluster-scoped.
	Cached bool `json:"cached,omitempty"`

	// The maximum number of clusters the given cluster can support in a ClusterMesh.
	MaxConnectedClusters uint32 `json:"maxConnectedClusters,omitempty"`
}

// ValidationMode defines if a missing CiliumClusterConfig should be allowed for
// backward compatibility, or it should be flagged as an error.
type ValidationMode bool

const (
	BackwardCompatible ValidationMode = false
	Strict             ValidationMode = true
)
