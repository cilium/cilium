// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// Cell implements the Cilium Network Driver for exposing
// network devices to workloads.
var Cell = cell.Module(
	"network-driver",
	"Cilium Network Driver",

	cell.ProvidePrivate(
		resourceClaimResource,
		podResource,
	),
	cell.Invoke(registerNetworkDriver),
)

type networkDriverParams struct {
	cell.In

	Log            *slog.Logger
	Lifecycle      cell.Lifecycle
	ClientSet      k8sClient.Clientset
	JobGroup       job.Group
	ResourceClaims resource.Resource[*resourceapi.ResourceClaim]
	Pods           resource.Resource[*corev1.Pod]
}

// getNetworkDriverConfig returns the network driver configuration.
// This will be deprecated in favor a configuration passed via a Custom Resource.
//
// An example configuration to manage dummy devices is:
//
//	{
//		DraRegistrationRetry:   time.Second,
//		DraRegistrationTimeout: 30 * time.Second,
//		PublishInterval:        3 * time.Second,
//		DriverName:             "dummy.cilium.k8s.io",
//		DeviceManagerConfigs: map[types.DeviceManagerType]types.DeviceManagerConfig{
//			types.DeviceManagerTypeDummy: dummy.DummyConfig{Enabled: true},
//		},
//		Pools: []PoolConfig{
//			{
//				Name: "dummy-devices",
//				Filter: types.DeviceFilter{
//					DriverTypes: []types.DeviceManagerType{types.DeviceManagerTypeDummy},
//					IfNames:     []string{"dummy"},
//				},
//			},
//		},
//	}
func getNetworkDriverConfig(_ k8sClient.Clientset) (*Config, error) {
	return nil, nil
}

func registerNetworkDriver(params networkDriverParams) *Driver {
	cfg, err := getNetworkDriverConfig(params.ClientSet)
	if err != nil {
		params.Log.Error(
			"failed to retrieve network driver configuration",
			logfields.Error, err,
		)

		return nil
	}

	if cfg == nil {
		params.Log.Debug(
			"network driver configuration not found, skipping",
		)

		return nil
	}

	driver := &Driver{
		driverName:     cfg.DriverName,
		logger:         params.Log,
		lock:           lock.Mutex{},
		jg:             params.JobGroup,
		resourceClaims: params.ResourceClaims,
		pods:           params.Pods,
		kubeClient:     params.ClientSet,
		config:         *cfg,
		deviceManagers: make(map[types.DeviceManagerType]types.DeviceManager),
		allocations:    make(map[kube_types.UID]map[kube_types.UID][]allocation),
	}

	params.Lifecycle.Append(driver)

	return driver
}
