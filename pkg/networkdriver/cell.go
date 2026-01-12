// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/option"
)

// Cell implements the Cilium Network Driver for exposing
// network devices to workloads.
var Cell = cell.Module(
	"network-driver",
	"Cilium Network Driver",

	cell.ProvidePrivate(ciliumNetworkDriverConfigResource),
	cell.Invoke(registerNetworkDriver),
)

type networkDriverParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	ClientSet k8sClient.Clientset
	JobGroup  job.Group
	Configs   resource.Resource[*v2alpha1.CiliumNetworkDriverConfig]
}

func ciliumNetworkDriverConfigResource(cs k8sClient.Clientset, lc cell.Lifecycle, mp workqueue.MetricsProvider, daemonCfg *option.DaemonConfig) resource.Resource[*v2alpha1.CiliumNetworkDriverConfig] {
	if !cs.IsEnabled() || !daemonCfg.EnableCiliumNetworkDriver {
		return nil
	}

	return resource.New[*v2alpha1.CiliumNetworkDriverConfig](
		lc,
		utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumNetworkDriverConfigs()),
		mp,
		resource.WithMetric("CiliumNetworkDriverConfig"),
	)
}

func registerNetworkDriver(params networkDriverParams) *Driver {
	driver := &Driver{
		logger:         params.Log,
		lock:           lock.Mutex{},
		jg:             params.JobGroup,
		kubeClient:     params.ClientSet,
		deviceManagers: make(map[types.DeviceManagerType]types.DeviceManager),
		configCRD:      params.Configs,
		allocations:    make(map[kube_types.UID]map[kube_types.UID][]allocation),
	}

	params.Lifecycle.Append(driver)

	return driver
}
