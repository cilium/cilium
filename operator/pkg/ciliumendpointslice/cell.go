// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"fmt"

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
	CESMaxCEPsInCES             int      `mapstructure:"ces-max-ciliumendpoints-per-ces"`
	CESSlicingMode              string   `mapstructure:"ces-slice-mode"`
	CESWriteQPSLimit            float64  `mapstructure:"ces-write-qps-limit" exhaustruct:"optional"`
	CESWriteQPSBurst            int      `mapstructure:"ces-write-qps-burst" exhaustruct:"optional"`
	CESEnableDynamicRateLimit   bool     `mapstructure:"ces-enable-dynamic-rate-limit" exhaustruct:"optional"`
	CESDynamicRateLimitNodes    []string `mapstructure:"ces-dynamic-rate-limit-nodes" exhaustruct:"optional"`
	CESDynamicRateLimitQPSLimit []string `mapstructure:"ces-dynamic-rate-limit-qps-limit" exhaustruct:"optional"`
	CESDynamicRateLimitQPSBurst []string `mapstructure:"ces-dynamic-rate-limit-qps-burst" exhaustruct:"optional"`
	CESDynamicRateLimitConfig   string   `mapstructure:"ces-rate-limits"`
}

var defaultConfig = Config{
	CESMaxCEPsInCES:           100,
	CESSlicingMode:            fcfsMode,
	CESDynamicRateLimitConfig: "[{\"nodes\":0,\"limit\":10,\"burst\":20}]",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	depUseDLR := fmt.Sprintf("dynamic rate limiting is now configured by default. Please use --%s to supply a custom config", CESRateLimits)
	flags.Int(CESMaxCEPsInCES, def.CESMaxCEPsInCES, "Maximum number of CiliumEndpoints allowed in a CES")
	flags.String(CESSlicingMode, def.CESSlicingMode, "Slicing mode defines how CiliumEndpoints are grouped into CES: either batched by their Identity (\"identity\") or batched on a \"First Come, First Served\" basis (\"fcfs\")")
	flags.MarkDeprecated(CESSlicingMode, "Slicing mode defaults to the FCFS mode and is now deprecated option. It does not have a functional effect")
	flags.Float64(CESWriteQPSLimit, def.CESWriteQPSLimit, "CES work queue rate limit. Ignored when "+CESEnableDynamicRateLimit+" is set")
	flags.MarkDeprecated(CESWriteQPSLimit, depUseDLR)
	flags.Int(CESWriteQPSBurst, def.CESWriteQPSBurst, "CES work queue burst rate. Ignored when "+CESEnableDynamicRateLimit+" is set")
	flags.MarkDeprecated(CESWriteQPSBurst, depUseDLR)

	flags.Bool(CESEnableDynamicRateLimit, def.CESEnableDynamicRateLimit, "Flag to enable dynamic rate limit specified in separate fields instead of the static one")
	flags.MarkDeprecated(CESEnableDynamicRateLimit, depUseDLR)
	flags.StringSlice(CESDynamicRateLimitNodes, def.CESDynamicRateLimitNodes, "List of nodes used for the dynamic rate limit steps")
	flags.MarkDeprecated(CESDynamicRateLimitNodes, depUseDLR)
	flags.StringSlice(CESDynamicRateLimitQPSLimit, def.CESDynamicRateLimitQPSLimit, "List of qps limits used for the dynamic rate limit steps")
	flags.MarkDeprecated(CESDynamicRateLimitQPSLimit, depUseDLR)
	flags.StringSlice(CESDynamicRateLimitQPSBurst, def.CESDynamicRateLimitQPSBurst, "List of qps burst used for the dynamic rate limit steps")
	flags.MarkDeprecated(CESDynamicRateLimitQPSBurst, depUseDLR)

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
