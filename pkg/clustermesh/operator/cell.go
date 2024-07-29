// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
)

const subsystem = "clustermesh"

// Cell is the cell for the Operator ClusterMesh
var Cell = cell.Module(
	"clustermesh",
	"Cell providing clustermesh capabilities in the operator",
	cell.Config(ClusterMeshConfig{}),
	cell.Config(MCSAPIConfig{}),
	cell.Provide(
		newClusterMesh,
		newAPIClustersHandler,
	),

	cell.Config(common.Config{}),
	cell.Config(wait.TimeoutConfigDefault),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(subsystem)),
)

type clusterMeshParams struct {
	cell.In

	common.Config
	wait.TimeoutConfig
	Cfg       ClusterMeshConfig
	CfgMCSAPI MCSAPIConfig
	Logger    logrus.FieldLogger

	// ClusterInfo is the id/name of the local cluster. This is used for logging and metrics
	ClusterInfo types.ClusterInfo

	Metrics       Metrics
	CommonMetrics common.Metrics
	StoreFactory  store.Factory

	// ServiceResolver, if not nil, is used to create a custom dialer for service resolution.
	ServiceResolver *dial.ServiceResolver
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

// MCSAPIConfig contains the configuration for MCS-API
type MCSAPIConfig struct {
	// ClusterMeshEnableMCSAPI enables the MCS API support
	ClusterMeshEnableMCSAPI bool `mapstructure:"clustermesh-enable-mcs-api"`
}

// Flags adds the flags used by ClientConfig.
func (cfg MCSAPIConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"clustermesh-enable-mcs-api",
		cfg.ClusterMeshEnableMCSAPI,
		"Whether or not the MCS API support is enabled.",
	)
}
