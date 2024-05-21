// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cilium/cilium/pkg/defaults"
)

const (
	// ClusterIDMin is the minimum value of the cluster ID
	ClusterIDMin    = 0
	ClusterIDExt511 = 511

	ClusterIDUnset = ClusterIDMin
)

// ClusterIDMax is the maximum value of the cluster ID
var ClusterIDMax uint32 = defaults.MaxConnectedClusters

// A cluster name must respect the following constraints:
// * It must contain at most 32 characters;
// * It must begin and end with a lower case alphanumeric character;
// * It may contain lower case alphanumeric characters and dashes between.
const (
	// clusterNameMaxLength is the maximum allowed length of a cluster name.
	clusterNameMaxLength = 32
	// clusterNameRegexStr is the regex to validate a cluster name.
	clusterNameRegexStr = `^([a-z0-9][-a-z0-9]*)?[a-z0-9]$`
)

var clusterNameRegex = regexp.MustCompile(clusterNameRegexStr)

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

// ValidateClusterName validates that the given name matches the cluster name specifications.
func ValidateClusterName(name string) error {
	if name == "" {
		return errors.New("must not be empty")
	}

	if len(name) > clusterNameMaxLength {
		return fmt.Errorf("must not be more than %d characters", clusterNameMaxLength)
	}

	if !clusterNameRegex.MatchString(name) {
		return errors.New("must consist of lower case alphanumeric characters and '-', and must start and end with an alphanumeric character")
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
