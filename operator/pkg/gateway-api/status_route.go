// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"slices"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func pruneRouteParentStatuses(parents []gatewayv1.RouteParentStatus, currentParentRefs []gatewayv1.ParentReference) []gatewayv1.RouteParentStatus {
	filtered := parents[:0]

	for _, parentStatus := range parents {
		if parentStatus.ControllerName != controllerName || slices.Contains(currentParentRefs, parentStatus.ParentRef) {
			filtered = append(filtered, parentStatus)
		}
	}

	return filtered
}
