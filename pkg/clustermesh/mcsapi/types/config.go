// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"
)

var DefaultMCSAPIConfig = MCSAPIConfig{
	EnableMCSAPI: false,
	InstallCRDs:  true,
}

// MCSAPIConfig contains the configuration for MCS-API
type MCSAPIConfig struct {
	// EnableMCSAPI enables the MCS API support
	EnableMCSAPI bool `mapstructure:"clustermesh-enable-mcs-api"`
	// InstallCRDs control whether to automatically install the MCS API CRDs
	// conditional on EnableMCSAPI being true
	InstallCRDs bool `mapstructure:"clustermesh-mcs-api-install-crds"`
}

// Flags adds the flags used by ClientConfig.
func (cfg MCSAPIConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"clustermesh-enable-mcs-api",
		cfg.EnableMCSAPI,
		"Enable Cluster Mesh MCS-API support",
	)
	flags.Bool(
		"clustermesh-mcs-api-install-crds",
		cfg.InstallCRDs,
		"Install and manage the MCS API CRDs. Only applicable if MCS API support is enabled.",
	)
}

func (cfg MCSAPIConfig) ShouldInstallMCSAPICrds() bool {
	return cfg.EnableMCSAPI && cfg.InstallCRDs
}
