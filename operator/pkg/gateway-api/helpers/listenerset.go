// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func HasListenerSetSupport(scheme *runtime.Scheme) bool {
	return scheme.Recognizes(gatewayv1.SchemeGroupVersion.WithKind("ListenerSet"))
}

func ListenerEntryToListener(entry gatewayv1.ListenerEntry) gatewayv1.Listener {
	// These currently have identical fields
	return gatewayv1.Listener(entry)
}

func ResolveListenerSetToGateway(
	ctx context.Context, c client.Client,
	lsName string, lsNamespace string,
) *types.NamespacedName {
	ls := &gatewayv1.ListenerSet{}
	nn := types.NamespacedName{Namespace: lsNamespace, Name: lsName}
	if err := c.Get(ctx, nn, ls); err != nil {
		return nil
	}

	return ListenerSetParentGateway(ls)
}

func ListenerSetParentGateway(ls *gatewayv1.ListenerSet) *types.NamespacedName {
	gwNamespace := ls.GetNamespace()
	if ls.Spec.ParentRef.Namespace != nil {
		gwNamespace = string(*ls.Spec.ParentRef.Namespace)
	}

	return &types.NamespacedName{
		Namespace: gwNamespace,
		Name:      string(ls.Spec.ParentRef.Name),
	}
}
