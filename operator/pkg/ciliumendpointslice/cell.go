// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// CESMaxCEPsInCES is the maximum number of cilium endpoints allowed in single
	// a CiliumEndpointSlice resource.
	CESMaxCEPsInCES = "ces-max-ciliumendpoints-per-ces"

	// CESSlicingMode instructs how CEPs are grouped in a CES.
	CESSlicingMode = "ces-slice-mode"

	// CESWriteQPSLimit is the rate limit per second for the CES work queue to
	// process  CES events that result in CES write (Create, Update, Delete)
	// requests to the kube-apiserver.
	CESWriteQPSLimit = "ces-write-qps-limit"

	// CESWriteQPSBurst is the burst rate per second used with CESWriteQPSLimit
	// for the CES work queue to process CES events that result in CES write
	// (Create, Update, Delete) requests to the kube-apiserver.
	CESWriteQPSBurst = "ces-write-qps-burst"

	// CESEnableDynamicRateLimit is used to ignore static QPS Limit and Burst
	// and use dynamic limit, burst and nodes instead.
	CESEnableDynamicRateLimit = "ces-enable-dynamic-rate-limit"

	// CESDynamicRateLimitNodes is used to specify the list of nodes used for the
	// dynamic rate limit steps.
	CESDynamicRateLimitNodes = "ces-dynamic-rate-limit-nodes"

	// CESDynamicRateLimitQPSLimit is used to specify the list of qps limits for the
	// dynamic rate limit steps.
	CESDynamicRateLimitQPSLimit = "ces-dynamic-rate-limit-qps-limit"

	// CESDynamicRateLimitQPSBurst is used to specify the list of qps bursts for the
	// dynamic rate limit steps.
	CESDynamicRateLimitQPSBurst = "ces-dynamic-rate-limit-qps-burst"
)

// Cell is a cell that implements a Cilium Endpoint Slice Controller.
// The controller subscribes to cilium endpoint and cilium endpoint slices
// events and reconciles the state of the cilium endpoint slices in the cluster.
var Cell = cell.Module(
	"k8s-ces-controller",
	"Cilium Endpoint Slice Controller",
	cell.Config(defaultConfig),
	cell.Invoke(registerController),
	cell.Metric(NewMetrics),
)

type Config struct {
	CESMaxCEPsInCES             int      `mapstructure:"ces-max-ciliumendpoints-per-ces"`
	CESSlicingMode              string   `mapstructure:"ces-slice-mode"`
	CESWriteQPSLimit            float64  `mapstructure:"ces-write-qps-limit"`
	CESWriteQPSBurst            int      `mapstructure:"ces-write-qps-burst"`
	CESEnableDynamicRateLimit   bool     `mapstructure:"ces-enable-dynamic-rate-limit"`
	CESDynamicRateLimitNodes    []string `mapstructure:"ces-dynamic-rate-limit-nodes"`
	CESDynamicRateLimitQPSLimit []string `mapstructure:"ces-dynamic-rate-limit-qps-limit"`
	CESDynamicRateLimitQPSBurst []string `mapstructure:"ces-dynamic-rate-limit-qps-burst"`
}

var defaultConfig = Config{
	CESMaxCEPsInCES:             100,
	CESSlicingMode:              "cesSliceModeIdentity",
	CESWriteQPSLimit:            10,
	CESWriteQPSBurst:            20,
	CESEnableDynamicRateLimit:   false,
	CESDynamicRateLimitNodes:    []string{},
	CESDynamicRateLimitQPSLimit: []string{},
	CESDynamicRateLimitQPSBurst: []string{},
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Int(CESMaxCEPsInCES, def.CESMaxCEPsInCES, "Maximum number of CiliumEndpoints allowed in a CES")
	flags.String(CESSlicingMode, def.CESSlicingMode, "Slicing mode define how ceps are grouped into a CES")
	flags.Float64(CESWriteQPSLimit, def.CESWriteQPSLimit, "CES work queue rate limit. Ignored when "+CESEnableDynamicRateLimit+" is set")
	flags.Int(CESWriteQPSBurst, def.CESWriteQPSBurst, "CES work queue burst rate. Ignored when "+CESEnableDynamicRateLimit+" is set")

	flags.Bool(CESEnableDynamicRateLimit, def.CESEnableDynamicRateLimit, "Flag to enable dynamic rate limit specified in separate fields instead of the static one")
	flags.StringSlice(CESDynamicRateLimitNodes, def.CESDynamicRateLimitNodes, "List of nodes used for the dynamic rate limit steps")
	flags.StringSlice(CESDynamicRateLimitQPSLimit, def.CESDynamicRateLimitQPSLimit, "List of qps limits used for the dynamic rate limit steps")
	flags.StringSlice(CESDynamicRateLimitQPSBurst, def.CESDynamicRateLimitQPSBurst, "List of qps burst used for the dynamic rate limit steps")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableCiliumEndpointSlice enables the cilium endpoint slicing feature and the CES Controller.
	EnableCiliumEndpointSlice bool
}
