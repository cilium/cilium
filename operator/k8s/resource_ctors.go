// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/cilium/pkg/hive"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CiliumEndpointResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2.CiliumEndpoint], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](cs.CiliumV2().CiliumEndpoints("")),
		opts...,
	)
	return resource.New[*cilium_api_v2.CiliumEndpoint](lc, lw, resource.WithMetric("CiliumEndpoint")), nil
}

func CiliumEndpointSliceResource(lc hive.Lifecycle, cs client.Clientset, opts ...func(*metav1.ListOptions)) (resource.Resource[*cilium_api_v2alpha1.CiliumEndpointSlice], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumEndpointSliceList](cs.CiliumV2alpha1().CiliumEndpointSlices()),
		opts...,
	)
	return resource.New[*cilium_api_v2alpha1.CiliumEndpointSlice](lc, lw, resource.WithMetric("CiliumEndpointSlice")), nil
}
