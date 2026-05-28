// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestCheckExtensionRefs(t *testing.T) {
	parentRef := gatewayv1.ParentReference{Name: "gateway"}

	tests := []struct {
		name       string
		input      *HTTPRouteInput
		wantResult bool
		wantReason gatewayv1.RouteConditionReason
	}{
		{
			name: "same namespace backend is allowed",
			input: httpRouteInputWithExtensionRef(
				"default",
				parentRef,
				extensionRef("ext-proc"),
				true,
				[]v2alpha1.CiliumEnvoyExtProcFilter{extProcFilter("default", "ext-proc", "ext-proc-service", nil)},
				nil,
			),
			wantResult: true,
		},
		{
			name: "feature disabled",
			input: httpRouteInputWithExtensionRef(
				"default",
				parentRef,
				extensionRef("ext-proc"),
				false,
				[]v2alpha1.CiliumEnvoyExtProcFilter{extProcFilter("default", "ext-proc", "ext-proc-service", nil)},
				nil,
			),
			wantReason: gatewayv1.RouteReasonInvalidKind,
		},
		{
			name: "unsupported ExtensionRef kind",
			input: httpRouteInputWithExtensionRef(
				"default",
				parentRef,
				gatewayv1.LocalObjectReference{Group: "example.com", Kind: "ExampleFilter", Name: "ext-proc"},
				true,
				nil,
				nil,
			),
			wantReason: gatewayv1.RouteReasonInvalidKind,
		},
		{
			name: "missing CiliumEnvoyExtProcFilter",
			input: httpRouteInputWithExtensionRef(
				"default",
				parentRef,
				extensionRef("missing"),
				true,
				nil,
				nil,
			),
			wantReason: gatewayv1.RouteReasonBackendNotFound,
		},
		{
			name: "cross namespace backend without ReferenceGrant",
			input: httpRouteInputWithExtensionRef(
				"default",
				parentRef,
				extensionRef("ext-proc"),
				true,
				[]v2alpha1.CiliumEnvoyExtProcFilter{extProcFilter("default", "ext-proc", "ext-proc-service", ptr.To("other"))},
				nil,
			),
			wantReason: gatewayv1.RouteReasonRefNotPermitted,
		},
		{
			name: "cross namespace backend with ReferenceGrant",
			input: httpRouteInputWithExtensionRef(
				"default",
				parentRef,
				extensionRef("ext-proc"),
				true,
				[]v2alpha1.CiliumEnvoyExtProcFilter{extProcFilter("default", "ext-proc", "ext-proc-service", ptr.To("other"))},
				[]gatewayv1.ReferenceGrant{extProcServiceReferenceGrant("other", "default", "ext-proc-service")},
			),
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, err := CheckExtensionRefs(tt.input, parentRef)
			require.NoError(t, err)
			require.Equal(t, tt.wantResult, gotResult)

			if tt.wantResult {
				require.Empty(t, tt.input.HTTPRoute.Status.Parents)
				return
			}

			require.Len(t, tt.input.HTTPRoute.Status.Parents, 1)
			conditions := tt.input.HTTPRoute.Status.Parents[0].Conditions
			require.Len(t, conditions, 1)
			require.Equal(t, string(gatewayv1.RouteConditionResolvedRefs), conditions[0].Type)
			require.Equal(t, metav1.ConditionFalse, conditions[0].Status)
			require.Equal(t, string(tt.wantReason), conditions[0].Reason)
		})
	}
}

func TestCheckExtensionRefs_GRPCRoute(t *testing.T) {
	parentRef := gatewayv1.ParentReference{Name: "gateway"}
	input := &GRPCRouteInput{
		Grants:                     &gatewayv1.ReferenceGrantList{},
		ExtensionRefFilters:        []v2alpha1.CiliumEnvoyExtProcFilter{extProcFilter("default", "ext-proc", "ext-proc-service", ptr.To("other"))},
		ExtensionRefFiltersEnabled: true,
		GRPCRoute: &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				Rules: []gatewayv1.GRPCRouteRule{
					{
						Filters: []gatewayv1.GRPCRouteFilter{
							{
								Type:         gatewayv1.GRPCRouteFilterExtensionRef,
								ExtensionRef: ptr.To(extensionRef("ext-proc")),
							},
						},
					},
				},
			},
		},
	}

	gotResult, err := CheckExtensionRefs(input, parentRef)
	require.NoError(t, err)
	require.False(t, gotResult)
	require.Len(t, input.GRPCRoute.Status.Parents, 1)
	require.Equal(t, string(gatewayv1.RouteReasonRefNotPermitted), input.GRPCRoute.Status.Parents[0].Conditions[0].Reason)
}

func TestCheckExtensionRefs_TLSRoute(t *testing.T) {
	parentRef := gatewayv1.ParentReference{Name: "gateway"}
	input := &TLSRouteInput{
		Grants: &gatewayv1.ReferenceGrantList{},
		TLSRoute: &gatewayv1.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
			Spec: gatewayv1.TLSRouteSpec{
				Rules: []gatewayv1.TLSRouteRule{{}},
			},
		},
	}

	gotResult, err := CheckExtensionRefs(input, parentRef)
	require.NoError(t, err)
	require.True(t, gotResult)
	require.Empty(t, input.TLSRoute.Status.Parents)
}

func httpRouteInputWithExtensionRef(namespace string, parentRef gatewayv1.ParentReference, ref gatewayv1.LocalObjectReference, enabled bool, filters []v2alpha1.CiliumEnvoyExtProcFilter, grants []gatewayv1.ReferenceGrant) *HTTPRouteInput {
	return &HTTPRouteInput{
		Grants:                     &gatewayv1.ReferenceGrantList{Items: grants},
		ExtensionRefFilters:        filters,
		ExtensionRefFiltersEnabled: enabled,
		HTTPRoute: &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Filters: []gatewayv1.HTTPRouteFilter{
							{
								Type:         gatewayv1.HTTPRouteFilterExtensionRef,
								ExtensionRef: ptr.To(ref),
							},
						},
					},
				},
			},
		},
	}
}

func extensionRef(name string) gatewayv1.LocalObjectReference {
	return gatewayv1.LocalObjectReference{
		Group: "cilium.io",
		Kind:  "CiliumEnvoyExtProcFilter",
		Name:  gatewayv1.ObjectName(name),
	}
}

func extProcFilter(namespace, name, backendName string, backendNamespace *string) v2alpha1.CiliumEnvoyExtProcFilter {
	return v2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
			BackendRef: v2alpha1.ExtProcBackendRef{
				Name:      backendName,
				Namespace: backendNamespace,
				Port:      4317,
			},
		},
	}
}

func extProcServiceReferenceGrant(targetNamespace, fromNamespace, serviceName string) gatewayv1.ReferenceGrant {
	return gatewayv1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-ext-proc",
			Namespace: targetNamespace,
		},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{
				{
					Group:     "cilium.io",
					Kind:      "CiliumEnvoyExtProcFilter",
					Namespace: gatewayv1.Namespace(fromNamespace),
				},
			},
			To: []gatewayv1.ReferenceGrantTo{
				{
					Group: "",
					Kind:  "Service",
					Name:  ptr.To(gatewayv1.ObjectName(serviceName)),
				},
			},
		},
	}
}
