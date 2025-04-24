// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/datapath/garp"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/dynamicconfig"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/redirectpolicy"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	k8s2 "github.com/cilium/cilium/pkg/policy/k8s"
	"github.com/cilium/cilium/pkg/promise"
)

var (
	// withDefaults will set enable all default metrics in the agent.
	withDefaults = os.Getenv("CILIUM_FEATURE_METRICS_WITH_DEFAULTS")
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
		func(m Metrics) api.PolicyMetrics {
			return m
		},
		func(m Metrics) redirectpolicy.LRPMetrics {
			return m
		},
		func(m Metrics) k8s.SVCMetrics {
			return m
		},
		func(m Metrics) ciliumenvoyconfig.FeatureMetrics {
			return m
		},
		func(m Metrics) k8s2.CNPMetrics {
			return m
		},
		func(m Metrics) clustermesh.ClusterMeshMetrics {
			return m
		},
	),
	metrics.Metric(func() Metrics {
		if withDefaults != "" {
			return NewMetrics(true)
		}
		return NewMetrics(false)
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

	LBConfig            loadbalancer.Config
	TunnelConfig        tunnel.Config
	CNIConfigManager    cni.CNIConfigManager
	MutualAuth          auth.MeshAuthConfig
	BandwidthManager    types.BandwidthManager
	BigTCP              types.BigTCPConfig
	L2PodAnnouncement   garp.L2PodAnnouncementConfig
	DynamicConfigSource dynamicconfig.ConfigSource
}

func (fp *featuresParams) TunnelProtocol() tunnel.EncapProtocol {
	return fp.TunnelConfig.EncapProtocol()
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

func (fp *featuresParams) IsL2PodAnnouncementEnabled() bool {
	return fp.L2PodAnnouncement.Enabled()
}

func (fp *featuresParams) IsDynamicConfigSourceKindNodeConfig() bool {
	return fp.DynamicConfigSource.IsKindNodeConfig()
}

type enabledFeatures interface {
	TunnelProtocol() tunnel.EncapProtocol
	GetChainingMode() string
	IsMutualAuthEnabled() bool
	IsBandwidthManagerEnabled() bool
	BigTCPConfig() types.BigTCPConfig
	IsL2PodAnnouncementEnabled() bool
	IsDynamicConfigSourceKindNodeConfig() bool
}
