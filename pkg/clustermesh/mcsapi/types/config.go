// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"
)

var DefaultMCSAPIConfig = MCSAPIConfig{
	ClusterMeshEnableMCSAPI:      false,
	ClusterMeshInstallMCSAPICRDs: true,
}

// MCSAPIConfig contains the configuration for MCS-API
type MCSAPIConfig struct {
	// ClusterMeshEnableMCSAPI enables the MCS API support
	ClusterMeshEnableMCSAPI bool `mapstructure:"clustermesh-enable-mcs-api"`
	// ClusterMeshInstallMCSAPICRDs control whether to automatically install the MCS API CRDs
	// conditional on ClusterMeshEnableMCSAPI being true
	ClusterMeshInstallMCSAPICRDs bool `mapstructure:"clustermesh-install-mcs-api-crds"`
}

// Flags adds the flags used by ClientConfig.
func (cfg MCSAPIConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"clustermesh-enable-mcs-api",
		cfg.ClusterMeshEnableMCSAPI,
		"Whether or not the MCS API support is enabled.",
	)
	flags.Bool(
		"clustermesh-install-mcs-api-crds",
		cfg.ClusterMeshInstallMCSAPICRDs,
		"Whether or not the MCS API CRDs should be automatically installed. "+
			"clustermesh-enable-mcs-api must be true for this to take effect.",
	)
}

func (cfg MCSAPIConfig) ShouldInstallMCSAPICrds() bool {
	return cfg.ClusterMeshEnableMCSAPI && cfg.ClusterMeshInstallMCSAPICRDs
}
