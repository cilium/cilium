// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

const (
	// CESMaxCEPsInCES is the maximum number of cilium endpoints allowed in single
	// a CiliumEndpointSlice resource.
	CESMaxCEPsInCES = "ces-max-ciliumendpoints-per-ces"

	// CESSlicingMode instructs how CEPs are grouped in a CES.
	CESSlicingMode = "ces-slice-mode"

	// CESRateLimits can be used to configure a custom, stepped dynamic rate limit based on cluster size.
	CESRateLimits = "ces-rate-limits"
)

// Cell is a cell that implements a Cilium Endpoint Slice Controller.
// The controller subscribes to cilium endpoint and cilium endpoint slices
// events and reconciles the state of the cilium endpoint slices in the cluster.
var Cell = cell.Module(
	"k8s-ces-controller",
	"Cilium Endpoint Slice Controller",
	cell.Config(defaultConfig),
	cell.Invoke(registerController),
	metrics.Metric(NewMetrics),
)

type Config struct {
	CESMaxCEPsInCES           int    `mapstructure:"ces-max-ciliumendpoints-per-ces"`
	CESSlicingMode            string `mapstructure:"ces-slice-mode"`
	CESDynamicRateLimitConfig string `mapstructure:"ces-rate-limits"`
}

var defaultConfig = Config{
	CESMaxCEPsInCES:           100,
	CESSlicingMode:            fcfsMode,
	CESDynamicRateLimitConfig: "[{\"nodes\":0,\"limit\":10,\"burst\":20}]",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Int(CESMaxCEPsInCES, def.CESMaxCEPsInCES, "Maximum number of CiliumEndpoints allowed in a CES")
	flags.String(CESSlicingMode, def.CESSlicingMode, "Slicing mode defines how CiliumEndpoints are grouped into CES: either batched by their Identity (\"identity\") or batched on a \"First Come, First Served\" basis (\"fcfs\")")
	flags.MarkDeprecated(CESSlicingMode, "Slicing mode defaults to the FCFS mode and is now deprecated option. It does not have a functional effect")

	flags.String(CESRateLimits, def.CESDynamicRateLimitConfig, "Configure rate limits for the CES controller. Accepts a list of rate limit configurations, must be a JSON formatted string.")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableCiliumEndpointSlice enables the cilium endpoint slicing feature and the CES Controller.
	EnableCiliumEndpointSlice bool
}
