// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// IndexListenerSetByGateway is a client.IndexerFunc that takes a single ListenerSet and returns
// the parent Gateway object full name (`namespace/name`) to add to the relevant index.
func IndexListenerSetByGateway(rawObj client.Object) []string {
	ls := rawObj.(*gatewayv1.ListenerSet)

	gwNamespace := ls.GetNamespace()
	if ls.Spec.ParentRef.Namespace != nil {
		gwNamespace = string(*ls.Spec.ParentRef.Namespace)
	}

	return []string{
		types.NamespacedName{
			Namespace: gwNamespace,
			Name:      string(ls.Spec.ParentRef.Name),
		}.String(),
	}
}
