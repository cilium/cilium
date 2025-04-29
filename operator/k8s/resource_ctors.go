// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/hive/cell"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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
			resource.WithMetric("Pod"),
			resource.WithIndexers(indexers),
		),
		nil
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

const ServiceIndex = "service"

func EndpointsResource(logger *slog.Logger, lc cell.Lifecycle, cfg k8s.ConfigParams, cs client.Clientset, mp workqueue.MetricsProvider) (resource.Resource[*k8s.Endpoints], error) {
	return k8s.EndpointsResourceWithIndexers(
		logger,
		lc,
		cfg,
		cs,
		cache.Indexers{
			// Index endpoints by their service identifier. Used by [ServiceSyncCell].
			ServiceIndex: func(obj any) ([]string, error) {
				eps, ok := obj.(*k8s.Endpoints)
				if !ok {
					return nil, fmt.Errorf("unexpected object type: %T", obj)
				}
				return []string{eps.ServiceName.String()}, nil
			},
		},
		mp,
	)
}
