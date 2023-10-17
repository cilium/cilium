// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func computeHosts[T ~string](gw *gatewayv1.Gateway, hostnames []T) []string {
	hosts := make([]string, 0, len(hostnames))
	for _, listener := range gw.Spec.Listeners {
		hosts = append(hosts, computeHostsForListener(&listener, hostnames)...)
	}

	return hosts
}

func computeHostsForListener[T ~string](listener *gatewayv1.Listener, hostnames []T) []string {
	return model.ComputeHosts(toStringSlice(hostnames), (*string)(listener.Hostname))
}

func toStringSlice[T ~string](s []T) []string {
	res := make([]string, 0, len(s))
	for _, h := range s {
		res = append(res, string(h))
	}
	return res
}
