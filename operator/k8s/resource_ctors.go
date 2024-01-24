// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"errors"
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

func CiliumEndpointResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumEndpoint], error) {
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
		lc, lw, resource.WithMetric("CiliumEndpoint"), resource.WithIndexers(indexers)), nil
}

func identityIndexFunc(obj interface{}) ([]string, error) {
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

func CiliumEndpointSliceResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](cs.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](lc, lw, resource.WithMetric("CiliumEndpointSlice")), nil
}

func CiliumNodeResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumNode], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](cs.CiliumV2().CiliumNodes()),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumNode](lc, lw,
		resource.WithMetric("CiliumNode"),
	), nil
}

func CiliumBGPClusterConfigResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPClusterConfigList](cs.CiliumV2alpha1().CiliumBGPClusterConfigs()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPClusterConfig](lc, lw, resource.WithMetric("CiliumBGPClusterConfig")), nil
}

func CiliumBGPNodeConfigOverrideResource(lc cell.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverrideList](cs.CiliumV2alpha1().CiliumBGPNodeConfigOverrides()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride](lc, lw, resource.WithMetric("CiliumBGPNodeConfigOverride")), nil
}
