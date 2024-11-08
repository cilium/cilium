// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell will retrieve information from all other cells /
// configuration to describe, in form of prometheus metrics, which
// features are enabled on the agent.
var Cell = cell.Module(
	"enabled-features",
	"Exports prometheus metrics describing which features are enabled in cilium-agent",

	cell.Invoke(updateAgentConfigMetricOnStart),
	cell.Provide(
		func(m Metrics) featureMetrics {
			return m
		},
	),
	metrics.Metric(func() Metrics {
		return NewMetrics(true)
	}),
)

type featuresParams struct {
	cell.In

	Log           *slog.Logger
	JobGroup      job.Group
	Health        cell.Health
	Lifecycle     cell.Lifecycle
	ConfigPromise promise.Promise[*option.DaemonConfig]
	Metrics       featureMetrics

	TunnelConfig     tunnel.Config
	CNIConfigManager cni.CNIConfigManager
	MutualAuth       auth.MeshAuthConfig
	BandwidthManager types.BandwidthManager
	BigTCP           types.BigTCPConfig
}

func (fp *featuresParams) TunnelProtocol() tunnel.Protocol {
	return fp.TunnelConfig.Protocol()
}

func (fp *featuresParams) GetChainingMode() string {
	return fp.CNIConfigManager.GetChainingMode()
}

func (fp *featuresParams) IsMutualAuthEnabled() bool {
	return fp.MutualAuth.IsEnabled()
}

func (fp *featuresParams) IsBandwidthManagerEnabled() bool {
	return fp.BandwidthManager.Enabled()
}

func (fp *featuresParams) BigTCPConfig() types.BigTCPConfig {
	return fp.BigTCP
}

type enabledFeatures interface {
	TunnelProtocol() tunnel.Protocol
	GetChainingMode() string
	IsMutualAuthEnabled() bool
	IsBandwidthManagerEnabled() bool
	BigTCPConfig() types.BigTCPConfig
}
