// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// HTTPRouteInput is used to implement the Input interface for HTTPRoute
type HTTPRouteInput struct {
	Ctx       context.Context
	Logger    *logrus.Entry
	Client    client.Client
	Grants    *gatewayv1beta1.ReferenceGrantList
	HTTPRoute *gatewayv1.HTTPRoute

	gateways map[gatewayv1.ParentReference]*gatewayv1.Gateway
}

func (h *HTTPRouteInput) SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = h.HTTPRoute.GetGeneration()

	h.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})

}

func (h *HTTPRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = h.HTTPRoute.GetGeneration()

	for _, parent := range h.HTTPRoute.Spec.ParentRefs {
		h.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}

}

func (h *HTTPRouteInput) mergeStatusConditions(parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range h.HTTPRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		h.HTTPRoute.Status.RouteStatus.Parents[index].Conditions = merge(h.HTTPRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	h.HTTPRoute.Status.RouteStatus.Parents = append(h.HTTPRoute.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}

func (h *HTTPRouteInput) GetGrants() []gatewayv1beta1.ReferenceGrant {
	return h.Grants.Items
}

func (h *HTTPRouteInput) GetNamespace() string {
	return h.HTTPRoute.GetNamespace()
}

func (h *HTTPRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute")
}

func (h *HTTPRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range h.HTTPRoute.Spec.Rules {
		rules = append(rules, &HTTPRouteRule{rule})
	}
	return rules
}

func (h *HTTPRouteInput) GetClient() client.Client {
	return h.Client
}

func (h *HTTPRouteInput) GetContext() context.Context {
	return h.Ctx
}

func (h *HTTPRouteInput) GetHostnames() []gatewayv1.Hostname {
	return h.HTTPRoute.Spec.Hostnames
}

func (h *HTTPRouteInput) GetGateway(parent gatewayv1.ParentReference) (*gatewayv1.Gateway, error) {
	if h.gateways == nil {
		h.gateways = make(map[gatewayv1.ParentReference]*gatewayv1.Gateway)
	}

	if gw, exists := h.gateways[parent]; exists {
		return gw, nil
	}

	ns := helpers.NamespaceDerefOr(parent.Namespace, h.GetNamespace())
	gw := &gatewayv1.Gateway{}

	if err := h.Client.Get(h.Ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			// if it is not just a not found error, we should return the error as something is bad
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}

		// Gateway does not exist skip further checks
		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}

	h.gateways[parent] = gw

	return gw, nil
}

func (h *HTTPRouteInput) Log() *logrus.Entry {
	return h.Logger
}

// HTTPRouteRule is used to implement the GenericRule interface for TLSRoute
type HTTPRouteRule struct {
	Rule gatewayv1.HTTPRouteRule
}

func (t *HTTPRouteRule) GetBackendRefs() []gatewayv1.BackendRef {
	var refs []gatewayv1.BackendRef
	for _, backend := range t.Rule.BackendRefs {
		refs = append(refs, backend.BackendRef)
	}
	for _, f := range t.Rule.Filters {
		if f.Type == gatewayv1.HTTPRouteFilterRequestMirror {
			if f.RequestMirror == nil {
				continue
			}
			refs = append(refs, gatewayv1.BackendRef{
				BackendObjectReference: f.RequestMirror.BackendRef,
			})
		}
	}
	return refs
}
