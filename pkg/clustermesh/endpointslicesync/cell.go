// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh/operator"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/metrics"
)

const subsystem = "clustermesh"

// Cell is the cell for the Operator ClusterMesh
var Cell = cell.Module(
	"endpointslicesync-clustermesh",
	"EndpointSlice clustermesh synchronization in the Cilium operator",
	cell.Config(EndpointSliceSyncConfig{}),
	cell.Invoke(registerEndpointSliceSync),

	metrics.Metric(NewMetrics),
)

type endpointSliceSyncParams struct {
	cell.In

	Logger *slog.Logger

	operator.ClusterMeshConfig
	EndpointSliceSyncConfig
	JobGroup job.Group

	Clientset   k8sClient.Clientset
	Services    resource.Resource[*slim_corev1.Service]
	ClusterMesh operator.ClusterMesh
}

// EndpointSliceSyncConfig contains the configuration for endpointSliceSync inside the operator.
type EndpointSliceSyncConfig struct {
	// ClusterMeshConcurrentEndpointSync the number of service endpoint syncing operations
	// that will be done concurrently by the EndpointSlice Cluster Mesh controller.
	ClusterMeshConcurrentEndpointSync int `mapstructure:"clustermesh-concurrent-service-endpoint-syncs"`
	// ClusterMeshEndpointUpdatesBatchPeriod describes the length of endpoint updates batching period.
	// Processing of cluster service changes will be delayed by this duration to join them with potential
	// upcoming updates and reduce the overall number of endpoints updates.
	ClusterMeshEndpointUpdatesBatchPeriod time.Duration `mapstructure:"clustermesh-endpoint-updates-batch-period"`
	// ClusterMeshEndpointsPerSlice is the maximum number of endpoints that
	// will be added to an EndpointSlice synced from a remote cluster.
	// More endpoints per slice will result in less endpoint slices, but larger resources. Defaults to 100.
	ClusterMeshMaxEndpointsPerSlice int `mapstructure:"clustermesh-endpoints-per-slice"`
}

// Flags adds the flags used by ClientConfig.
func (cfg EndpointSliceSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.IntVar(&cfg.ClusterMeshConcurrentEndpointSync,
		"clustermesh-concurrent-service-endpoint-syncs",
		5, // This currently mirrors the same default value as the endpointslice Kubernetes controller https://github.com/kubernetes/kubernetes/blob/v1.29.0/cmd/kube-controller-manager/app/options/endpointslicecontroller.go#L45
		"The number of remote cluster service syncing operations that will be done concurrently. Larger number = faster endpoint slice updating, but more CPU (and network) load.",
	)
	flags.DurationVar(&cfg.ClusterMeshEndpointUpdatesBatchPeriod,
		"clustermesh-endpoint-updates-batch-period",
		time.Millisecond*500,
		"The length of endpoint slice updates batching period for remote cluster services. Processing of pod changes will be delayed by this duration to join them with potential upcoming updates and reduce the overall number of endpoints updates. Larger number = higher endpoint programming latency, but lower number of endpoints revision generated.",
	)
	flags.IntVar(&cfg.ClusterMeshMaxEndpointsPerSlice,
		"clustermesh-endpoints-per-slice",
		100,
		"The maximum number of endpoints that will be added to a remote cluster's EndpointSlice . More endpoints per slice will result in less endpoint slices, but larger resources.",
	)
}
