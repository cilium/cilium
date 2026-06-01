// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"slices"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func pruneRouteParentStatuses(parents []gatewayv1.RouteParentStatus, currentParentRefs []gatewayv1.ParentReference) []gatewayv1.RouteParentStatus {
	filtered := parents[:0]

	for _, parentStatus := range parents {
		if parentStatus.ControllerName != helpers.CiliumDefaultControllerName || slices.Contains(currentParentRefs, parentStatus.ParentRef) {
			filtered = append(filtered, parentStatus)
		}
	}

	return filtered
}
