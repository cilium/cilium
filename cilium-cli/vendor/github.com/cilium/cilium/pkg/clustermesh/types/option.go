// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
)

const (
	// OptClusterName is the name of the OptClusterName option
	OptClusterName = "cluster-name"

	// OptClusterID is the name of the OptClusterID option
	OptClusterID = "cluster-id"
)

// ClusterInfo groups together the ClusterID and the ClusterName
type ClusterInfo struct {
	ID   uint32 `mapstructure:"cluster-id"`
	Name string `mapstructure:"cluster-name"`
}

// DefaultClusterInfo represents the default ClusterInfo values.
var DefaultClusterInfo = ClusterInfo{
	ID:   0,
	Name: defaults.ClusterName,
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (def ClusterInfo) Flags(flags *pflag.FlagSet) {
	flags.Uint32(OptClusterID, def.ID, "Unique identifier of the cluster")
	flags.String(OptClusterName, def.Name, "Name of the cluster")
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

func (c ClusterInfo) validateName() error {
	if c.ID != 0 && c.Name == defaults.ClusterName {
		return fmt.Errorf("cannot use default cluster name (%s) with option %s",
			defaults.ClusterName, OptClusterID)
	}

	return nil
}
