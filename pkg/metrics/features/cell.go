// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"os"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/clustermesh"
	garpTypes "github.com/cilium/cilium/pkg/datapath/garp/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/redirectpolicy"
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

	cell.Invoke(newAgentConfigMetricOnStart),
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
		func(m Metrics) watchers.CECMetrics {
			return m
		},
		func(m Metrics) watchers.CNPMetrics {
			return m
		},
		func(m Metrics) clustermesh.ClusterMeshMetrics {
			return m
		},
	),
	cell.Metric(func() Metrics {
		if withDefaults != "" {
			return NewMetrics(true)
		}
		return NewMetrics(false)
	}),
)

type featuresParams struct {
	cell.In

	Scope         cell.Scope
	JobRegistry   job.Registry
	Health        cell.Health
	Lifecycle     cell.Lifecycle
	ConfigPromise promise.Promise[*option.DaemonConfig]
	Metrics       featureMetrics

	TunnelConfig      tunnel.Config
	CNIConfigManager  cni.CNIConfigManager
	MutualAuth        auth.MeshAuthConfig
	BandwidthManager  types.BandwidthManager
	BigTCP            types.BigTCPConfig
	L2PodAnnouncement garpTypes.L2PodAnnouncementConfig
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

func (fp *featuresParams) IsL2PodAnnouncementEnabled() bool {
	return fp.L2PodAnnouncement.Enabled()
}

type enabledFeatures interface {
	TunnelProtocol() tunnel.Protocol
	GetChainingMode() string
	IsMutualAuthEnabled() bool
	IsBandwidthManagerEnabled() bool
	BigTCPConfig() types.BigTCPConfig
	IsL2PodAnnouncementEnabled() bool
}
