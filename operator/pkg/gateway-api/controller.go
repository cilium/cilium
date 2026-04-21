// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// controllerName is the gateway controller name used in cilium.
	controllerName = "io.cilium/gateway-controller"
)

func hasMatchingController(ctx context.Context, c client.Client, controllerName string, logger *slog.Logger) func(object client.Object) bool {
	return func(obj client.Object) bool {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)
		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return false
		}

		gwc := &gatewayv1.GatewayClass{}
		key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
		if err := c.Get(ctx, key, gwc); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to get GatewayClass", logfields.Error, err)
			return false
		}

		return string(gwc.Spec.ControllerName) == controllerName
	}
}

// onlyStatusChanged returns true if and only if there is status change for underlying objects.
// Supported objects are GatewayClass, Gateway, HTTPRoute and GRPCRoute
func onlyStatusChanged() predicate.Predicate {
	option := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			switch e.ObjectOld.(type) {
			case *gatewayv1.GatewayClass:
				o, _ := e.ObjectOld.(*gatewayv1.GatewayClass)
				n, ok := e.ObjectNew.(*gatewayv1.GatewayClass)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1.Gateway:
				o, _ := e.ObjectOld.(*gatewayv1.Gateway)
				n, ok := e.ObjectNew.(*gatewayv1.Gateway)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1.HTTPRoute:
				o, _ := e.ObjectOld.(*gatewayv1.HTTPRoute)
				n, ok := e.ObjectNew.(*gatewayv1.HTTPRoute)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1.TLSRoute:
				o, _ := e.ObjectOld.(*gatewayv1.TLSRoute)
				n, ok := e.ObjectNew.(*gatewayv1.TLSRoute)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			case *gatewayv1.GRPCRoute:
				o, _ := e.ObjectOld.(*gatewayv1.GRPCRoute)
				n, ok := e.ObjectNew.(*gatewayv1.GRPCRoute)
				if !ok {
					return false
				}
				return !cmp.Equal(o.Status, n.Status, option)
			default:
				return false
			}
		},
	}
}
