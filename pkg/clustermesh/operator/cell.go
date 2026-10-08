// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	cmendpointslice "github.com/cilium/cilium/pkg/clustermesh/endpointslice"
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
	cell.Config(types.DefaultServiceModeV2Config),
	cell.Invoke(types.ServiceModeV2Config.Validate),
	Enable(func(cfg ClusterMeshConfig) bool {
		return cfg.ClusterMeshEnableEndpointSync
	}),
	cell.ProvidePrivate(toEnabled),
	cell.Provide(
		common.DefaultRemoteClientFactory,
		newClusterMesh,
		newAPIClustersHandler,
	),
	cell.ProvidePrivate(common.NewClusterIDsManager),

	cell.Config(common.DefaultConfig),
	cell.Config(wait.TimeoutConfigDefault),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(metrics.SubsystemClusterMesh)),
	metrics.Metric(cmendpointslice.MetricsProvider(metrics.CiliumOperatorNamespace)),
	cmendpointslice.Cell,
)

type clusterMeshParams struct {
	cell.In

	common.Config
	types.ServiceModeV2Config
	wait.TimeoutConfig
	Cfg    ClusterMeshConfig
	Logger *slog.Logger

	// ClusterInfo is the id/name of the local cluster.
	ClusterInfo types.ClusterInfo

	// RemoteClientFactory is the factory to create new backend instances.
	RemoteClientFactory common.RemoteClientFactoryFn

	Metrics           Metrics
	CommonMetrics     common.Metrics
	StoreFactory      store.Factory
	ClusterIDsManager common.ClusterIDsManager

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

// enabler is the type to request enabling the operator ClusterMesh cell
type enabler bool

// enabled is the type representing whether the operator CluterMesh is requested to be enabled.
type enabled bool

// Enable allows to enable the ClusterMesh Cell. The cell is enabled if at
// least one Enable instance returns true.
func Enable[T any](fn func(T) bool) cell.Cell {
	return cell.Provide(func(cfg T) (out struct {
		cell.Out
		Enabler enabler `group:"request-enable-clustermesh"`
	}) {
		out.Enabler = enabler(fn(cfg))
		return out
	})
}

// toEnabled summarizes the outputs of [Enable] into a single [enabled] value.
func toEnabled(in struct {
	cell.In

	Enablers []enabler `group:"request-enable-clustermesh"`
}) (en enabled) {
	return enabled(slices.Contains(in.Enablers, enabler(true)))
}
