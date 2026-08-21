// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/spf13/pflag"
)

const (
	// Flag to enable BGP control plane features
	EnableBGPControlPlane = "enable-bgp-control-plane"

	// EnableBGPControlPlaneStatusReport enables BGP Control Plane CRD status reporting
	EnableBGPControlPlaneStatusReport = "enable-bgp-control-plane-status-report"

	// Enables advertising LoadBalancerIP routes with the BGP ORIGIN
	// attribute set to INCOMPLETE (2), matching MetalLB’s legacy behavior,
	// instead of the default IGP (0).
	EnableBGPLegacyOriginAttribute = "enable-bgp-legacy-origin-attribute"

	// BGPSecretsNamespace is the Kubernetes namespace to get BGP control plane secrets from.
	BGPSecretsNamespace = "bgp-secrets-namespace"

	// BGP router-id allocation mode
	BGPRouterIDAllocationMode = "bgp-router-id-allocation-mode"

	// BGP router-id allocation IP pool
	BGPRouterIDAllocationIPPool = "bgp-router-id-allocation-ip-pool"
)

type BGPConfig struct {
	// Enables BGP control plane features.
	Enable bool `mapstructure:"enable-bgp-control-plane"`

	// Enables BGP control plane status reporting.
	EnableStatusReport bool `mapstructure:"enable-bgp-control-plane-status-report"`

	// Enables LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE
	EnableLegacyOriginAttribute bool `mapstructure:"enable-bgp-legacy-origin-attribute"`

	// SecretsNamespace is the Kubernetes namespace to get BGP control plane secrets from.
	SecretsNamespace string `mapstructure:"bgp-secrets-namespace"`

	// RouterIDAllocationMode is the mode to allocate the BGP router-id.
	RouterIDAllocationMode BGPRouterIDAllocationModeType `mapstructure:"bgp-router-id-allocation-mode"`

	// RouterIDAllocationIPPool is the IP pool to allocate the BGP router-id from.
	RouterIDAllocationIPPool string `mapstructure:"bgp-router-id-allocation-ip-pool"`
}

var DefaultConfig = BGPConfig{
	EnableLegacyOriginAttribute: false,
	SecretsNamespace:            "",
	Enable:                      false,
	EnableStatusReport:          true,
	RouterIDAllocationMode:      BGPRouterIDAllocationModeDefault,
	RouterIDAllocationIPPool:    "",
}

func (def BGPConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableBGPLegacyOriginAttribute, def.EnableLegacyOriginAttribute, "Enable LoadBalancerIP routes to be advertised with BGP Origin Attribute set to INCOMPLETE")
	flags.Bool(EnableBGPControlPlane, def.Enable, "Enable the BGP control plane")
	flags.Bool(EnableBGPControlPlaneStatusReport, def.EnableStatusReport, "Enable the BGP control plane status reporting")
	flags.Var(&(def.RouterIDAllocationMode), BGPRouterIDAllocationMode, "BGP router-id allocation mode. Currently supported values: 'default' or 'ip-pool'")
	flags.String(BGPRouterIDAllocationIPPool, def.RouterIDAllocationIPPool, "IP pool to allocate the BGP router-id from when the mode is 'ip-pool'")
	flags.String(BGPSecretsNamespace, def.SecretsNamespace, "Kubernetes namespace to get BGP control plane secrets from")
}

func (def BGPConfig) BGPControlPlaneEnabled() bool {
	return def.Enable
}
