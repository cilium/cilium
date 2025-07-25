// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"
)

var DefaultMCSAPIConfig = MCSAPIConfig{
	ClusterMeshEnableMCSAPI: false,
}

// MCSAPIConfig contains the configuration for MCS-API
type MCSAPIConfig struct {
	// ClusterMeshEnableMCSAPI enables the MCS API support
	ClusterMeshEnableMCSAPI bool `mapstructure:"clustermesh-enable-mcs-api"`
}

// Flags adds the flags used by ClientConfig.
func (cfg MCSAPIConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"clustermesh-enable-mcs-api",
		cfg.ClusterMeshEnableMCSAPI,
		"Enable Cluster Mesh MCS-API support",
	)
}
