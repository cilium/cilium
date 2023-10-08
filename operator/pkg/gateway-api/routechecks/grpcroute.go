// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

var _ Input = (*GRPCRouteInput)(nil)

// GRPCRouteInput is used to implement the Input interface for GRPCRoute
type GRPCRouteInput struct {
	Ctx       context.Context
	Logger    *logrus.Entry
	Client    client.Client
	Grants    *gatewayv1beta1.ReferenceGrantList
	GRPCRoute *gatewayv1alpha2.GRPCRoute

	gateways map[gatewayv1.ParentReference]*gatewayv1.Gateway
}

// GRPCRouteRule is used to implement the GenericRule interface for GRPCRoute
type GRPCRouteRule struct {
	Rule gatewayv1alpha2.GRPCRouteRule
}

func (g *GRPCRouteRule) GetBackendRefs() []gatewayv1.BackendRef {
	var refs []gatewayv1.BackendRef
	for _, b := range g.Rule.BackendRefs {
		refs = append(refs, b.BackendRef)
	}

	for _, f := range g.Rule.Filters {
		if f.Type == gatewayv1alpha2.GRPCRouteFilterRequestMirror {
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

func (g *GRPCRouteInput) GetRules() []GenericRule {
	var rules []GenericRule
	for _, rule := range g.GRPCRoute.Spec.Rules {
		rules = append(rules, &GRPCRouteRule{rule})
	}
	return rules
}

func (g *GRPCRouteInput) GetNamespace() string {
	return g.GRPCRoute.GetNamespace()
}

func (g *GRPCRouteInput) GetClient() client.Client {
	return g.Client
}

func (g *GRPCRouteInput) GetContext() context.Context {
	return g.Ctx
}

func (g *GRPCRouteInput) GetGVK() schema.GroupVersionKind {
	return gatewayv1alpha2.SchemeGroupVersion.WithKind("GRPCRoute")
}

func (g *GRPCRouteInput) GetGrants() []gatewayv1beta1.ReferenceGrant {
	return g.Grants.Items
}

func (g *GRPCRouteInput) GetGateway(parent gatewayv1.ParentReference) (*gatewayv1.Gateway, error) {
	if g.gateways == nil {
		g.gateways = make(map[gatewayv1.ParentReference]*gatewayv1.Gateway)
	}

	if gw, exists := g.gateways[parent]; exists {
		return gw, nil
	}

	ns := helpers.NamespaceDerefOr(parent.Namespace, g.GetNamespace())
	gw := &gatewayv1.Gateway{}

	if err := g.Client.Get(g.Ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
		if !k8serrors.IsNotFound(err) {
			// if it is not just a not found error, we should return the error as something is bad
			return nil, fmt.Errorf("error while getting gateway: %w", err)
		}

		// Gateway does not exist skip further checks
		return nil, fmt.Errorf("gateway %q does not exist: %w", parent.Name, err)
	}

	g.gateways[parent] = gw
	return gw, nil
}

func (g *GRPCRouteInput) GetHostnames() []gatewayv1beta1.Hostname {
	return g.GRPCRoute.Spec.Hostnames
}

func (g *GRPCRouteInput) SetParentCondition(ref gatewayv1beta1.ParentReference, condition metav1.Condition) {
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = g.GRPCRoute.GetGeneration()

	g.mergeStatusConditions(ref, []metav1.Condition{
		condition,
	})
}

func (g *GRPCRouteInput) SetAllParentCondition(condition metav1.Condition) {
	// fill in the condition
	condition.LastTransitionTime = metav1.NewTime(time.Now())
	condition.ObservedGeneration = g.GRPCRoute.GetGeneration()

	for _, parent := range g.GRPCRoute.Spec.ParentRefs {
		g.mergeStatusConditions(parent, []metav1.Condition{
			condition,
		})
	}
}

func (g *GRPCRouteInput) Log() *logrus.Entry {
	return g.Logger
}

func (g *GRPCRouteInput) mergeStatusConditions(parentRef gatewayv1alpha2.ParentReference, updates []metav1.Condition) {
	index := -1
	for i, parent := range g.GRPCRoute.Status.RouteStatus.Parents {
		if reflect.DeepEqual(parent.ParentRef, parentRef) {
			index = i
			break
		}
	}
	if index != -1 {
		g.GRPCRoute.Status.RouteStatus.Parents[index].Conditions = merge(g.GRPCRoute.Status.RouteStatus.Parents[index].Conditions, updates...)
		return
	}
	g.GRPCRoute.Status.RouteStatus.Parents = append(g.GRPCRoute.Status.RouteStatus.Parents, gatewayv1alpha2.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: controllerName,
		Conditions:     updates,
	})
}
