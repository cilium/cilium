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
}

func (c0 *CiliumClusterConfig) IsCompatible(c1 *CiliumClusterConfig) error {
	if c1 == nil {
		// When remote cluster doesn't have cluster config, we
		// currently just bypass the validation for compatibility.
		// Otherwise, we cannot connect with older cluster which
		// doesn't support cluster config feature.
		//
		// When we introduce a new cluster config can't be ignored,
		// we should properly check it here and return error. Now
		// we only have ClusterID which used to be ignored.
		return nil
	} else {
		// Remote cluster has cluster config. Do validations.

		// ID shouldn't be duplicated
		if c0.ID == c1.ID {
			return fmt.Errorf("duplicated cluster id")
		}
	}
	return nil
}
