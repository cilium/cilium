// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestGatewayAPIInferencePoolWithExtensionRef(t *testing.T) {
	pool := gateway_inf_ext.InferencePool{
		ObjectMeta: metav1.ObjectMeta{Name: "llm-pool", Namespace: "default"},
		Spec: gateway_inf_ext.InferencePoolSpec{
			EndpointPickerRef: &gateway_inf_ext.EndpointPickerRef{
				Name:        "llm-pool-epp",
				Port:        &gateway_inf_ext.Port{Number: 9002},
				FailureMode: gateway_inf_ext.EndpointPickerFailOpen,
			},
		},
	}

	tests := map[string]struct {
		matches        []gatewayv1.HTTPRouteMatch
		enableFilters  bool
		includeFilter  bool
		wantFailClosed bool
	}{
		"implicit match keeps inference backend and extension filter": {
			enableFilters: true,
			includeFilter: true,
		},
		"every explicit match keeps inference backend and extension filter": {
			matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchExact), Value: ptr.To("/first")}},
				{Path: &gatewayv1.HTTPPathMatch{Type: ptr.To(gatewayv1.PathMatchExact), Value: ptr.To("/second")}},
			},
			enableFilters: true,
			includeFilter: true,
		},
		"disabled extension filter fails closed despite valid inference backend": {
			includeFilter:  true,
			wantFailClosed: true,
		},
		"unresolved extension filter fails closed despite valid inference backend": {
			enableFilters:  true,
			wantFailClosed: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			route := testHTTPRoute([]gatewayv1.HTTPRouteFilter{extProcHTTPFilter("filter-a")})
			route.Spec.ParentRefs = []gatewayv1.ParentReference{{Name: "gateway"}}
			route.Spec.Rules[0].Matches = tc.matches
			route.Spec.Rules[0].BackendRefs = []gatewayv1.HTTPBackendRef{{
				BackendRef: gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{
					Group: ptr.To(gatewayv1.Group(gateway_inf_ext.GroupName)),
					Kind:  ptr.To(gatewayv1.Kind("InferencePool")),
					Name:  gatewayv1.ObjectName(pool.Name),
				}},
			}}
			input := Input{
				Gateway: gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"},
					Spec: gatewayv1.GatewaySpec{Listeners: []gatewayv1.Listener{{
						Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
					}}},
				},
				HTTPRoutes: []gatewayv1.HTTPRoute{route},
				Services: []corev1.Service{
					testService("default", helpers.ShadowServiceName(pool.Name), 8000),
					testService("default", "ext-proc", 9001),
				},
				InferencePools:            []gateway_inf_ext.InferencePool{pool},
				EnableExtensionRefFilters: tc.enableFilters,
			}
			if tc.includeFilter {
				input.CiliumEnvoyExtProcFilters = []v2alpha1.CiliumEnvoyExtProcFilter{extProcTestCRD("filter-a", "ext-proc", 9001)}
			}
			setTestMergedListeners(&input, nil)

			m := GatewayAPI(hivetest.Logger(t), input)
			require.Len(t, m.HTTP, 1)
			require.Len(t, m.HTTP[0].Routes, max(1, len(tc.matches)))
			for _, ingested := range m.HTTP[0].Routes {
				if tc.wantFailClosed {
					require.NotNil(t, ingested.DirectResponse)
					assert.Equal(t, 500, ingested.DirectResponse.StatusCode)
					assert.Empty(t, ingested.Backends)
					assert.Empty(t, ingested.ExtensionRefFilters)
					continue
				}

				assert.Nil(t, ingested.DirectResponse)
				require.Len(t, ingested.Backends, 1)
				assert.Equal(t, model.Backend{
					Name: helpers.ShadowServiceName(pool.Name), Namespace: "default",
					Port:           &model.BackendPort{Port: 8000},
					EndpointPicker: &model.EndpointPicker{Name: "llm-pool-epp", Namespace: "default", Port: 9002, FailureMode: "FailOpen"},
				}, ingested.Backends[0])
				require.Len(t, ingested.ExtensionRefFilters, 1)
				filter := ingested.ExtensionRefFilters[0]
				assert.Equal(t, "envoy.filters.http.ext_proc/default/filter-a", filter.Name)
				assert.Equal(t, model.ExtProcExternalProcessorTypeURL, filter.TypeURL)
				assert.NotEmpty(t, filter.Config)
				assert.Equal(t, &model.Backend{Name: "ext-proc", Namespace: "default", Port: &model.BackendPort{Port: 9001}}, filter.Backend)
				require.NotNil(t, filter.SourceRouteRule)
				assert.Equal(t, route.Name, filter.SourceRouteRule.Source.Name)
				assert.Equal(t, 0, filter.SourceRouteRule.RuleIndex)
			}
		})
	}
}
