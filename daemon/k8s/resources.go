// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/util/workqueue"

	envoy "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
	// agent. Each of the resources share a client-go informer and backing store so we only
	// have one watch API call for each resource kind and that we maintain only one copy of each object.
	//
	// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.
	ResourcesCell = cell.Module(
		"k8s-resources",
		"Agent Kubernetes resources",

		cell.Config(k8s.DefaultConfig),
		cell.Provide(provideK8sWatchConfig),
		LocalNodeCell,
		cell.Provide(
			k8s.NetworkPolicyResource,
			k8s.CiliumNetworkPolicyResource,
			k8s.CiliumClusterwideNetworkPolicyResource,
			k8s.CiliumCIDRGroupResource,
			k8s.CiliumNodeResource,
			k8s.CiliumSlimEndpointResource,
			k8s.CiliumEndpointSliceResource,
		),
	)

	LocalNodeCell = cell.Module(
		"k8s-local-node-resources",
		"Agent Kubernetes local node resources",

		cell.Provide(
			func(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider) (LocalNodeResource, error) {
				return k8s.NodeResource(
					lc, cs, mp,
					func(opts *metav1.ListOptions) {
						opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodeTypes.GetName()).String()
					},
				)
			},
			func(params k8s.CiliumResourceParams) (LocalCiliumNodeResource, error) {
				return k8s.CiliumNodeResource(
					params,
					func(opts *metav1.ListOptions) {
						opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodeTypes.GetName()).String()
					},
				)
			},
		),
	)
)

// provideK8sWatchConfig creates k8s.ServiceWatchConfig with headless service watch
// enabled only if features relying on it (Gateway API, Ingress) are enabled.
//
// This reduces the load on apiserver in clusters that use headless services
// and don't use Ingress nor Gateway.
// See: https://github.com/cilium/cilium/issues/40763
func provideK8sWatchConfig(envoyCfg envoy.SecretSyncConfig) k8s.ServiceWatchConfig {
	return k8s.ServiceWatchConfig{
		EnableHeadlessServiceWatch: envoyCfg.EnableGatewayAPI || envoyCfg.EnableIngressController,
	}
}

// LocalNodeResource is a resource.Resource[*slim_corev1.Node] but one which will only stream updates for the node object
// associated with the node we are currently running on.
type LocalNodeResource resource.Resource[*slim_corev1.Node]

// LocalCiliumNodeResource is a resource.Resource[*cilium_api_v2.CiliumNode] but one which will only stream updates for the
// CiliumNode object associated with the node we are currently running on.
type LocalCiliumNodeResource resource.Resource[*cilium_api_v2.CiliumNode]
