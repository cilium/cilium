// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
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

// ValidationMode defines if a missing CiliumClusterConfig should be allowed for
// backward compatibility, or it should be flagged as an error.
type ValidationMode bool

const (
	BackwardCompatible ValidationMode = false
	Strict             ValidationMode = true
)

// Validate validates the configuration correctness. When the validation mode
// is BackwardCompatible, a missing configuration or with ID=0 is allowed for
// backward compatibility, otherwise it is flagged as an error.
func (c *CiliumClusterConfig) Validate(mode ValidationMode) error {
	if c == nil || c.ID == 0 {
		if mode == Strict {
			return errors.New("remote cluster is missing cluster configuration")
		}

		return nil
	}

	if err := ValidateClusterID(c.ID); err != nil {
		return err
	}

	return nil
}
