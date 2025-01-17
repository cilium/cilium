// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

const (
	// OptClusterName is the name of the OptClusterName option
	OptClusterName = "cluster-name"

	// OptClusterID is the name of the OptClusterID option
	OptClusterID = "cluster-id"

	// OptMaxConnectedClusters is the name of the OptMaxConnectedClusters option
	OptMaxConnectedClusters = "max-connected-clusters"
)

// ClusterInfo groups together the ClusterID and the ClusterName
type ClusterInfo struct {
	ID                   uint32 `mapstructure:"cluster-id"`
	Name                 string `mapstructure:"cluster-name"`
	MaxConnectedClusters uint32 `mapstructure:"max-connected-clusters"`
}

// DefaultClusterInfo represents the default ClusterInfo values.
var DefaultClusterInfo = ClusterInfo{
	ID:                   0,
	Name:                 defaults.ClusterName,
	MaxConnectedClusters: defaults.MaxConnectedClusters,
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (def ClusterInfo) Flags(flags *pflag.FlagSet) {
	flags.Uint32(OptClusterID, def.ID, "Unique identifier of the cluster")
	flags.String(OptClusterName, def.Name, "Name of the cluster. It must consist of at most 32 lower case alphanumeric characters and '-', start and end with an alphanumeric character.")
	flags.Uint32(OptMaxConnectedClusters, def.MaxConnectedClusters, "Maximum number of clusters to be connected in a clustermesh. Increasing this value will reduce the maximum number of identities available. Valid configurations are [255, 511].")
}

// Validate validates that the ClusterID is in the valid range (including ClusterID == 0),
// and that the ClusterName is different from the default value if the ClusterID != 0.
func (c ClusterInfo) Validate() error {
	if c.ID < ClusterIDMin || c.ID > ClusterIDMax {
		return fmt.Errorf("invalid cluster id %d: must be in range %d..%d",
			c.ID, ClusterIDMin, ClusterIDMax)
	}

	return c.validateName()
}

// ValidateStrict validates that the ClusterID is in the valid range, but not 0,
// and that the ClusterName is different from the default value.
func (c ClusterInfo) ValidateStrict() error {
	if err := ValidateClusterID(c.ID); err != nil {
		return err
	}

	return c.validateName()
}

// ValidateBuggyClusterID returns an error if a buggy cluster ID (i.e., with the
// 7th bit set) is used in combination with ENI IPAM mode or AWS CNI chaining.
func (c ClusterInfo) ValidateBuggyClusterID(ipamMode, chainingMode string) error {
	if (c.ID&0x80) != 0 && (ipamMode == ipamOption.IPAMENI || ipamMode == ipamOption.IPAMAlibabaCloud || chainingMode == "aws-cni") {
		return errors.New("Cilium is currently affected by a bug that causes traffic matched " +
			"by network policies to be incorrectly dropped when running in either ENI mode (both " +
			"AWS and AlibabaCloud) or AWS VPC CNI chaining mode, if the cluster ID is 128-255 (and " +
			"384-511 when max-connected-clusters=511). " +
			"Please refer to https://github.com/cilium/cilium/issues/21330 for additional details.")
	}

	return nil
}

func (c ClusterInfo) validateName() error {
	if err := ValidateClusterName(c.Name); err != nil {
		return fmt.Errorf("invalid cluster name: %w", err)
	}

	if c.ID != 0 && c.Name == defaults.ClusterName {
		return fmt.Errorf("cannot use default cluster name (%s) with option %s",
			defaults.ClusterName, OptClusterID)
	}

	return nil
}

// ExtendedClusterMeshEnabled returns true if MaxConnectedClusters value has
// been set to a value larger than the default 255.
func (c ClusterInfo) ExtendedClusterMeshEnabled() bool {
	return c.MaxConnectedClusters != defaults.MaxConnectedClusters
}

// ValidateRemoteConfig validates the remote CiliumClusterConfig to ensure
// compatibility with this cluster's configuration.
func (c ClusterInfo) ValidateRemoteConfig(config CiliumClusterConfig) error {
	if err := ValidateClusterID(config.ID); err != nil {
		return err
	}

	if c.ExtendedClusterMeshEnabled() && (c.MaxConnectedClusters != config.Capabilities.MaxConnectedClusters) {
		return fmt.Errorf("mismatched MaxConnectedClusters; local=%d, remote=%d", c.MaxConnectedClusters, config.Capabilities.MaxConnectedClusters)
	}

	return nil
}
