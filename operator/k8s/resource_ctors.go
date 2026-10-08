// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func CiliumEndpointResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumEndpoint], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](cs.CiliumV2().CiliumEndpoints("")),
		opts...,
	)
	indexers := cache.Indexers{
		cache.NamespaceIndex:        cache.MetaNamespaceIndexFunc,
		CiliumEndpointIndexIdentity: identityIndexFunc,
	}
	return resource.New[*cilium_api_v2.CiliumEndpoint](
		lc, lw, mp, resource.WithMetric("CiliumEndpoint"), resource.WithIndexers(indexers)), nil
}

func identityIndexFunc(obj any) ([]string, error) {
	switch t := obj.(type) {
	case *cilium_api_v2.CiliumEndpoint:
		if t.Status.Identity != nil {
			id := strconv.FormatInt(t.Status.Identity.ID, 10)
			return []string{id}, nil
		}
		return []string{"0"}, nil
	}
	return nil, fmt.Errorf("%w - found %T", errors.New("object is not a *cilium_api_v2.CiliumEndpoint"), obj)
}

func CiliumEndpointSliceResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](cs.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](lc, lw, mp, resource.WithMetric("CiliumEndpointSlice")), nil
}

func CiliumNodeResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](cs.CiliumV2().CiliumNodes()),
		opts...,
	)
	indexers := cache.Indexers{
		// This index will be used to create CES from pods.
		CiliumNodeIPIndex: CiliumNodeIPIndexFunc,
	}
	return resource.New[*cilium_api_v2.CiliumNode](lc, lw, mp,
		resource.WithMetric("CiliumNode"),
		resource.WithIndexers(indexers),
	), nil
}

func CiliumBGPClusterConfigResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumBGPClusterConfig], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumBGPClusterConfigList](cs.CiliumV2().CiliumBGPClusterConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumBGPClusterConfig](lc, lw, mp, resource.WithMetric("CiliumBGPClusterConfig")), nil
}

func CiliumBGPNodeConfigOverrideResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumBGPNodeConfigOverride], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumBGPNodeConfigOverrideList](cs.CiliumV2().CiliumBGPNodeConfigOverrides()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumBGPNodeConfigOverride](lc, lw, mp, resource.WithMetric("CiliumBGPNodeConfigOverride")), nil
}

func PodResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Pod], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.PodList](cs.Slim().CoreV1().Pods("")),
		opts...,
	)

	indexers := cache.Indexers{
		// The index will be used only by Operator Managing CIDs to reconcile NS labels changes.
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		// Thix index is used for IPAM by the ciliumNodeSynchronizer.
		PodNodeNameIndex: PodNodeNameIndexFunc,
	}

	return resource.New[*slim_corev1.Pod](lc, lw, mp,
			resource.WithTransform(TransformToOperatorPod),
			resource.WithMetric("Pod"),
			resource.WithIndexers(indexers),
		),
		nil
}

// TransformToOperatorPod strips the fields of a Pod which no consumer of
// PodResource reads, before the object is stored.
//
// The retained set is the union of what the consumers actually use:
//
//   - IPAM surge allocation (operator/pkg/ipam/nodemanager): spec.nodeName (via
//     PodNodeNameIndex), spec.hostNetwork, status.phase
//   - endpoint GC (operator/endpointgc): status.phase
//   - kvstore node GC (operator/pkg/kvstore/nodesgc): spec.nodeName,
//     status.phase, labels
//   - CiliumIdentity reconciler (operator/pkg/ciliumidentity): namespace,
//     labels, spec.serviceAccountName, spec.hostNetwork
//   - CiliumEndpointSlice (operator/pkg/ciliumendpointslice): name, namespace,
//     uid, labels, spec.{nodeName,hostNetwork,serviceAccountName},
//     spec.containers[].ports, status.{podIPs,hostIP}
//
// Note that the two standalone pod informers in operator/watchers have their own
// transforms and their own field sets.
func TransformToOperatorPod(pod *slim_corev1.Pod) (*slim_corev1.Pod, error) {
	// Only the named ports of the containers are read, by GetPodMetadata and by
	// the CiliumEndpointSlice reconciler, so containers without ports carry no
	// information at all.
	var containers []slim_corev1.Container
	for _, c := range pod.Spec.Containers {
		if len(c.Ports) == 0 {
			continue
		}
		containers = append(containers, slim_corev1.Container{Ports: c.Ports})
	}

	stripped := &slim_corev1.Pod{
		TypeMeta: pod.TypeMeta,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            pod.Name,
			Namespace:       pod.Namespace,
			UID:             pod.UID,
			ResourceVersion: pod.ResourceVersion,
			Labels:          pod.Labels,
		},
		Spec: slim_corev1.PodSpec{
			Containers:         containers,
			ServiceAccountName: pod.Spec.ServiceAccountName,
			NodeName:           pod.Spec.NodeName,
			HostNetwork:        pod.Spec.HostNetwork,
		},
		Status: slim_corev1.PodStatus{
			Phase:  pod.Status.Phase,
			HostIP: pod.Status.HostIP,
			PodIPs: pod.Status.PodIPs,
		},
	}

	// Small GC optimization: a transform is only ever handed a freshly decoded
	// object, referenced by nothing but the delta being processed (see
	// resource.WithTransform), so zeroing it drops the last reference to
	// everything not retained above without waiting for the delta itself to
	// become garbage. The retained labels and ports are unaffected: stripped
	// holds copies of their map and slice headers.
	*pod = slim_corev1.Pod{}

	return stripped, nil
}

func NodeResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*slim_corev1.Node], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](cs.Slim().CoreV1().Nodes()),
		opts...,
	)

	return resource.New[*slim_corev1.Node](
			lc, lw, mp,
			resource.WithTransform(TransformToOperatorNode),
			resource.WithMetric("Node"),
		),
		nil
}

// TransformToOperatorNode strips the fields of a Node which no consumer of
// NodeResource reads, before the object is stored.
//
// The retained set is the union of what the consumers actually use:
//
//   - node taint sync (operator/watchers): spec.taints, status.conditions
//   - CiliumNode GC (operator/watchers): existence only, keyed by name
func TransformToOperatorNode(node *slim_corev1.Node) (*slim_corev1.Node, error) {
	stripped := &slim_corev1.Node{
		TypeMeta: node.TypeMeta,
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            node.Name,
			ResourceVersion: node.ResourceVersion,
		},
		Spec: slim_corev1.NodeSpec{
			Taints: node.Spec.Taints,
		},
		Status: slim_corev1.NodeStatus{
			Conditions: node.Status.Conditions,
		},
	}

	// Small GC optimization, as in TransformToOperatorPod: the transform is
	// only ever handed a freshly decoded object, so zeroing it drops the last
	// reference to everything not retained above. The retained taints and
	// conditions are unaffected, as stripped holds copies of their slice
	// headers.
	*node = slim_corev1.Node{}

	return stripped, nil
}

func LBIPPoolsResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumLoadBalancerIPPool], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.CiliumV2().CiliumLoadBalancerIPPools()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumLoadBalancerIPPool](lc, lw, mp, resource.WithMetric("CiliumLoadBalancerIPPool")), nil
}

func ServiceExportResource(lc cell.Lifecycle, cs client.Clientset, mp workqueue.MetricsProvider, opts ...func(*metav1.ListOptions)) (resource.Resource[*mcsapiv1beta1.ServiceExport], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.MulticlusterV1beta1().ServiceExports("")),
		opts...,
	)
	return resource.New[*mcsapiv1beta1.ServiceExport](
		lc,
		lw,
		mp,
		resource.WithIndexers(cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}),
		resource.WithMetric("ServiceExport"),
	), nil
}

const ServiceIndex = "service"

func EndpointSliceResource(lc cell.Lifecycle, cfg k8s.ConfigParams, cs client.Clientset, mp workqueue.MetricsProvider) (resource.Resource[*slim_discovery_v1.EndpointSlice], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	endpointSliceOptsModifier, err := utils.GetEndpointSliceListOptionsModifier(cfg.Config.K8sServiceProxyName, cfg.WatchConfig.EnableHeadlessServiceWatch)
	if err != nil {
		return nil, err
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.Slim().DiscoveryV1().EndpointSlices("")),
		endpointSliceOptsModifier,
	)
	return resource.New[*slim_discovery_v1.EndpointSlice](
		lc,
		lw,
		mp,
		resource.WithMetric("EndpointSlice"),
		resource.WithIndexers(cache.Indexers{
			// Index endpoint slices by their namespace. Used by Cluster Mesh syncing to handle Global Namespaces.
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			// Index endpoint slices by their service identifier. Used by Cluster Mesh syncing.
			ServiceIndex: func(obj any) ([]string, error) {
				eps, ok := obj.(*slim_discovery_v1.EndpointSlice)
				if !ok {
					return nil, fmt.Errorf("unexpected object type: %T", obj)
				}
				serviceName := eps.Labels[slim_discovery_v1.LabelServiceName]
				if serviceName == "" {
					return []string{}, nil
				}
				return []string{eps.Namespace + "/" + serviceName}, nil
			},
		}),
	), nil
}
