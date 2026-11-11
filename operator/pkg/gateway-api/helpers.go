// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"maps"

	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func GatewayAddressTypePtr(addr gatewayv1.AddressType) *gatewayv1.AddressType {
	return &addr
}

func computeHostsForListener[T ~string](listener *gatewayv1.Listener, hostnames []T, excludeHostNames []T) []string {
	return model.ComputeHosts(toStringSlice(hostnames), (*string)(listener.Hostname), toStringSlice(excludeHostNames))
}

func toStringSlice[T ~string](s []T) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	} else {
		maps.Copy(left, right)
	}
	return left
}

func setMergedLabelsAndAnnotations(temp, desired client.Object) {
	temp.SetAnnotations(mergeMap(temp.GetAnnotations(), desired.GetAnnotations()))
	temp.SetLabels(mergeMap(temp.GetLabels(), desired.GetLabels()))
}

func gatewayFQR(gw *gatewayv1.Gateway) model.FullyQualifiedResource {
	return model.FullyQualifiedResource{
		Name:      gw.GetName(),
		Namespace: gw.GetNamespace(),
		Group:     gatewayv1.GroupVersion.Group,
		Version:   gatewayv1.GroupVersion.Version,
		Kind:      "Gateway",
		UID:       string(gw.GetUID()),
	}
}

func listenerSetFQR(ls *gatewayv1.ListenerSet) model.FullyQualifiedResource {
	return model.FullyQualifiedResource{
		Name:      ls.GetName(),
		Namespace: ls.GetNamespace(),
		Group:     gatewayv1.GroupVersion.Group,
		Version:   gatewayv1.GroupVersion.Version,
		Kind:      "ListenerSet",
		UID:       string(ls.GetUID()),
	}
}
