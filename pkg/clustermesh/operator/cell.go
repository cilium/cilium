// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
)

// Cell is the cell for the Operator ClusterMesh
var Cell = cell.Module(
	"clustermesh",
	"Cell providing clustermesh capabilities in the operator",
	cell.Config(ClusterMeshConfig{}),
	cell.Config(mcsapitypes.DefaultMCSAPIConfig),
	cell.Provide(
		common.DefaultRemoteClientFactory,
		newClusterMesh,
		newAPIClustersHandler,
	),

	cell.Config(common.DefaultConfig),
	cell.Config(wait.TimeoutConfigDefault),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(metrics.SubsystemClusterMesh)),
)

type clusterMeshParams struct {
	cell.In

	common.Config
	wait.TimeoutConfig
	Cfg       ClusterMeshConfig
	CfgMCSAPI mcsapitypes.MCSAPIConfig
	Logger    *slog.Logger

	// ClusterInfo is the id/name of the local cluster.
	ClusterInfo types.ClusterInfo

	// RemoteClientFactory is the factory to create new backend instances.
	RemoteClientFactory common.RemoteClientFactoryFn

	Metrics       Metrics
	CommonMetrics common.Metrics
	StoreFactory  store.Factory

	// ServiceResolver, if not nil, is used to create a custom dialer for service resolution.
	ServiceResolver dial.Resolver

	// ObserverFactories is the list of factories to instantiate additional observers.
	ObserverFactories []observer.Factory `group:"clustermesh-observers"`
}

// ClusterMeshConfig contains the configuration for ClusterMesh inside the operator.
type ClusterMeshConfig struct {
	// ClusterMeshEnableEndpointSync enables the EndpointSlice Cluster Mesh synchronization
	ClusterMeshEnableEndpointSync bool `mapstructure:"clustermesh-enable-endpoint-sync"`
}

// Flags adds the flags used by ClientConfig.
func (cfg ClusterMeshConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"clustermesh-enable-endpoint-sync",
		cfg.ClusterMeshEnableEndpointSync,
		"Whether or not the endpoint slice cluster mesh synchronization is enabled.",
	)
}
