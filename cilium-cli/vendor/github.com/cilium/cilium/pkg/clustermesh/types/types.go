// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
)

const (
	// ClusterIDMin is the minimum value of the cluster ID
	ClusterIDMin = 0

	// ClusterIDMax is the maximum value of the cluster ID
	ClusterIDMax = 255
)

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
}

func (c *CiliumClusterConfig) Validate() error {
	if c == nil || c.ID == 0 {
		// When remote cluster doesn't have cluster config, we
		// currently just bypass the validation for compatibility.
		// Otherwise, we cannot connect with older cluster which
		// doesn't support cluster config feature.
		//
		// When we introduce a new cluster config can't be ignored,
		// we should properly check it here and return error. Now
		// we only have ClusterID which used to be ignored.
		return nil
	}

	if err := ValidateClusterID(c.ID); err != nil {
		return err
	}

	return nil
}

// ClusterIDName groups together the ClusterID and the ClusterName
type ClusterIDName struct {
	ClusterID   uint32
	ClusterName string
}
