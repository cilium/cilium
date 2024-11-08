// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// features are enabled on the agent.
var Cell = cell.Module(
	"enabled-features",
	"Exports prometheus metrics describing which features are enabled in cilium-agent",

	cell.Invoke(newAgentConfigMetricOnStart),
	cell.Provide(
		func(m Metrics) featureMetrics {
			return m
		},
	),
	cell.Metric(func() Metrics {
		return NewMetrics(true)
	}),
)

type featuresParams struct {
	cell.In

	JobRegistry      job.Registry
	Health           cell.Health
	Lifecycle        cell.Lifecycle
	ConfigPromise    promise.Promise[*option.DaemonConfig]
	Metrics          featureMetrics
	CNIConfigManager cni.CNIConfigManager
	MutualAuth       auth.MeshAuthConfig
}

func (fp *featuresParams) TunnelProtocol() string {
	return option.Config.TunnelProtocol
}

func (fp *featuresParams) GetChainingMode() string {
	return fp.CNIConfigManager.GetChainingMode()
}

func (fp *featuresParams) IsMutualAuthEnabled() bool {
	return fp.MutualAuth.IsEnabled()
}

func (fp *featuresParams) IsBandwidthManagerEnabled() bool {
	return option.Config.EnableBandwidthManager
}

func (fp *featuresParams) BigTCPConfig() types.BigTCPConfig {
	return types.BigTCPUserConfig{
		EnableIPv4BIGTCP: option.Config.EnableIPv4BIGTCP,
		EnableIPv6BIGTCP: option.Config.EnableIPv6BIGTCP,
	}
}

type enabledFeatures interface {
	TunnelProtocol() string
	GetChainingMode() string
	IsMutualAuthEnabled() bool
	IsBandwidthManagerEnabled() bool
	BigTCPConfig() types.BigTCPConfig
}
