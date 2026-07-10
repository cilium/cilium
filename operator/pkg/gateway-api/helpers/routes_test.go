// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsParentAttachable(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		reconcileParent metav1.Object
		route           metav1.Object
		parents         []gatewayv1.RouteParentStatus
		want            bool
	}{
		{
			name: "Gateway parent, all okay",
			reconcileParent: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gateway",
				nil),
			parents: parentStatus("gateway",
				nil,
				true),
			want: true,
		},
		{
			name: "Gateway parent, Not Accepted",
			reconcileParent: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gateway",
				nil),
			parents: parentStatus("gateway",
				nil,
				false),
			want: false,
		},
		{
			name: "Gateway parent, Accepted but namespace mismatch",
			reconcileParent: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gateway",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gateway",
				ptr.To("otherns")),
			parents: parentStatus("gateway",
				ptr.To("otherns"),
				true),
			want: false,
		},

		{
			name: "GAMMA Service parent, same namespace",
			reconcileParent: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gammaParent",
					Namespace: "testns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"gammaParent",
				nil),
			parents: parentStatus("gammaParent",
				nil,
				true),

			want: true,
		},
		{
			name: "GAMMA Service parent, diff namespace",
			reconcileParent: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gammaParent",
					Namespace: "otherns",
				},
			},
			route: httpRouteWithParentAndStatus("gammaRoute",
				"testns",
				"",
				ptr.To("otherns")),
			parents: parentStatus("gateway",
				ptr.To("otherns"),
				false),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsParentAttachable(context.Background(), tt.reconcileParent, tt.route, tt.parents, nil)
			// TODO: update the condition below to compare got with tt.want.
			if tt.want != got {
				t.Errorf("IsParentAttachable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func httpRouteWithParentAndStatus(name, ns, parentName string, parentNS *string) *gatewayv1.HTTPRoute {
	gwParentName := gatewayv1.ObjectName(parentName)
	var gwParentNS *gatewayv1.Namespace
	if parentNS != nil {
		tempNS := gatewayv1.Namespace(*parentNS)
		gwParentNS = &tempNS
	} else {
		gwParentNS = nil
	}

	parentRef := gatewayv1.ParentReference{
		Name:      gwParentName,
		Namespace: gwParentNS,
	}
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					parentRef,
				},
			},
		},
	}
}

func parentStatus(parentName string, parentNS *string, status bool) []gatewayv1.RouteParentStatus {
	gwParentName := gatewayv1.ObjectName(parentName)
	var gwParentNS *gatewayv1.Namespace
	if parentNS != nil {
		tempNS := gatewayv1.Namespace(*parentNS)
		gwParentNS = &tempNS
	} else {
		gwParentNS = nil
	}

	parentRef := gatewayv1.ParentReference{
		Name:      gwParentName,
		Namespace: gwParentNS,
	}
	var condStatus metav1.ConditionStatus

	if status {
		condStatus = metav1.ConditionTrue
	} else {
		condStatus = metav1.ConditionFalse
	}

	return []gatewayv1.RouteParentStatus{
		{
			ParentRef: parentRef,
			Conditions: []metav1.Condition{
				{
					Type:   "Accepted",
					Status: condStatus,
				},
				{
					Type:   "ResolvedRefs",
					Status: condStatus,
				},
			},
		},
	}
}
