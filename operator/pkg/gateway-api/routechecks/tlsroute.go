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

// TLSRouteInput is used to implement the Input interface for TLSRoute
type TLSRouteInput struct {
	Ctx      context.Context
	Logger   *logrus.Entry
	Client   client.Client
	Grants   *gatewayv1beta1.ReferenceGrantList
	TLSRoute *gatewayv1alpha2.TLSRoute

	gateways map[gatewayv1.ParentReference]*gatewayv1.Gateway
}

func (t *TLSRouteInput) SetParentCondition(ref gatewayv1.ParentReference, condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = t.TLSRoute.GetGeneration()

	t.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})

}

func (t *TLSRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = t.TLSRoute.GetGeneration()

	for _, parent := range t.TLSRoute.Spec.ParentRefs {
		t.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}

}

func (t *TLSRouteInput) mergeStatusConditions(parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range t.TLSRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		t.TLSRoute.Status.RouteStatus.Parents[index].Conditions = merge(t.TLSRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	t.TLSRoute.Status.RouteStatus.Parents = append(t.TLSRoute.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}

func (t *TLSRouteInput) GetGrants() []gatewayv1beta1.ReferenceGrant {
	return t.Grants.Items
}

func (t *TLSRouteInput) GetNamespace() string {
	return t.TLSRoute.GetNamespace()
}

func (t *TLSRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1alpha2.SchemeGroupVersion.WithKind("TLSRoute")
}

func (t *TLSRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range t.TLSRoute.Spec.Rules {
		rules = append(rules, &TLSRouteRule{rule})
	}
	return rules
}

func (t *TLSRouteInput) GetClient() client.Client {
	return t.Client
}

func (t *TLSRouteInput) GetContext() context.Context {
	return t.Ctx
}

// TLSRouteRule is used to implement the GenericRule interface for TLSRoute
type TLSRouteRule struct {
	Rule gatewayv1alpha2.TLSRouteRule
}

func (t *TLSRouteRule) GetBackendRefs() []gatewayv1.BackendRef {
	return t.Rule.BackendRefs
}

func (t *TLSRouteInput) GetHostnames() []gatewayv1.Hostname {
	return t.TLSRoute.Spec.Hostnames
}

func (t *TLSRouteInput) GetGateway(parent gatewayv1.ParentReference) (*gatewayv1.Gateway, error) {
	if t.gateways == nil {
		t.gateways = make(map[gatewayv1.ParentReference]*gatewayv1.Gateway)
	}

	if gw, exists := t.gateways[parent]; exists {
		return gw, nil
	}

	ns := helpers.NamespaceDerefOr(parent.Namespace, t.GetNamespace())
	gw := &gatewayv1.Gateway{}

	if err := t.Client.Get(t.Ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			// if it is not just a not found error, we should return the error as something is bad
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}

		// Gateway does not exist skip further checks
		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}

	t.gateways[parent] = gw

	return gw, nil
}

func (t *TLSRouteInput) Log() *logrus.Entry {
	return t.Logger
}
