// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

// ListenerSetListeners projects a ListenerSet's entries onto the Gateway Listener
// shape so the existing listener helpers/checks can be reused unchanged.
func ListenerSetListeners(ls *gatewayv1.ListenerSet) []gatewayv1.Listener {
	listeners := make([]gatewayv1.Listener, 0, len(ls.Spec.Listeners))

	for _, entry := range ls.Spec.Listeners {
		listeners = append(listeners, gatewayv1.Listener{
			Name:          entry.Name,
			Hostname:      entry.Hostname,
			Port:          entry.Port,
			Protocol:      entry.Protocol,
			TLS:           entry.TLS,
			AllowedRoutes: entry.AllowedRoutes,
		})
	}

	return listeners
}
