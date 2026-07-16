// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kube_types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

// Cell implements the Cilium Network Driver for exposing
// network devices to workloads.
var Cell = cell.Module(
	"network-driver",
	"Cilium Network Driver",

	cell.Config(defaultNetworkDriverConfig),

	cell.ProvidePrivate(
		ciliumNetworkDriverConfigResource,
		resourceClaimResource,
		podResource,
	),
	cell.Invoke(registerNetworkDriver),
)

type NetworkDriverConfig struct {
	Enabled bool `mapstructure:"enable-network-driver"`
}

func (cfg NetworkDriverConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(
		"enable-network-driver",
		cfg.Enabled,
		"enable network driver to assign interfaces via Dynamic Resource Allocation",
	)
}

var defaultNetworkDriverConfig = NetworkDriverConfig{
	Enabled: false,
}

type networkDriverParams struct {
	cell.In

	Log            *slog.Logger
	Lifecycle      cell.Lifecycle
	ClientSet      k8sClient.Clientset
	JobGroup       job.Group
	Configs        resource.Resource[*v2alpha1.CiliumNetworkDriverNodeConfig]
	ResourceClaims resource.Resource[*resourceapi.ResourceClaim]
	Pods           resource.Resource[*corev1.Pod]
	DaemonCfg      *option.DaemonConfig
	DB             *statedb.DB
	LocalNodeStore *node.LocalNodeStore
}

func ciliumNetworkDriverConfigResource(cs k8sClient.Clientset, lc cell.Lifecycle, mp workqueue.MetricsProvider, cfg NetworkDriverConfig) resource.Resource[*v2alpha1.CiliumNetworkDriverNodeConfig] {
	if !cs.IsEnabled() || !cfg.Enabled {
		return nil
	}

	return resource.New[*v2alpha1.CiliumNetworkDriverNodeConfig](
		lc,
		utils.ListerWatcherWithModifier(
			utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs()),
			func(opts *metav1.ListOptions) {
				opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodetypes.GetName()).String()
			}),
		mp,
		resource.WithMetric("CiliumNetworkDriverConfig"),
	)
}

func resourceClaimResource(
	lc cell.Lifecycle,
	cs k8sClient.Clientset,
	mp workqueue.MetricsProvider,
	crdSync promise.Promise[synced.CRDSync],
) (resource.Resource[*resourceapi.ResourceClaim], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(utils.ListerWatcherFromTyped(cs.ResourceV1().ResourceClaims("")))
	return resource.New[*resourceapi.ResourceClaim](
		lc, lw, mp,
		resource.WithMetric("ResourceClaim"),
		resource.WithCRDSync(crdSync),
	), nil
}

func podResource(
	lc cell.Lifecycle,
	cs k8sClient.Clientset,
	mp workqueue.MetricsProvider,
) (resource.Resource[*corev1.Pod], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.CoreV1().Pods("")),
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + nodetypes.GetName()).String()
		},
	)
	return resource.New[*corev1.Pod](lc, lw, mp,
		resource.WithMetric("Pod"),
	), nil
}

func registerNetworkDriver(params networkDriverParams) *Driver {
	driver := &Driver{
		logger:         params.Log,
		jg:             params.JobGroup,
		resourceClaims: params.ResourceClaims,
		pods:           params.Pods,
		kubeClient:     params.ClientSet,
		deviceManagers: make(map[types.DeviceManagerType]types.DeviceManager),
		configCRD:      params.Configs,
		allocations:    make(map[kube_types.UID]map[kube_types.UID][]allocation),
		podNetns:       make(map[kube_types.UID]string),
		db:             params.DB,
		localNodeStore: params.LocalNodeStore,
	}

	params.Lifecycle.Append(driver)

	return driver
}
