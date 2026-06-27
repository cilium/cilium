// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"log/slog"
	"testing"
	"time"

	ext_procv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/operator/pkg/model"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func Test_resolveExtensionRef(t *testing.T) {
	extProcFilters := []v2alpha1.CiliumEnvoyExtProcFilter{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-ext-proc",
				Namespace: "default",
			},
			Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
				BackendRef: v2alpha1.ExtProcBackendRef{
					Name: "ext-proc-service",
					Port: 9001,
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cross-ns-ext-proc",
				Namespace: "default",
			},
			Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
				BackendRef: v2alpha1.ExtProcBackendRef{
					Name:      "ext-proc-service",
					Namespace: ptr.To("other-namespace"),
					Port:      9002,
				},
			},
		},
	}

	tests := map[string]struct {
		enableExtensionRefFilters bool
		namespace                 string
		ref                       *gatewayv1.LocalObjectReference
		expectedFilter            *model.ExtensionRefFilter
		expectedOK                bool
	}{
		"feature disabled": {
			enableExtensionRefFilters: false,
			namespace:                 "default",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("cilium.io"),
				Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
				Name:  "my-ext-proc",
			},
			expectedFilter: nil,
			expectedOK:     false,
		},
		"wrong group": {
			enableExtensionRefFilters: true,
			namespace:                 "default",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("wrong.io"),
				Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
				Name:  "my-ext-proc",
			},
			expectedFilter: nil,
			expectedOK:     false,
		},
		"wrong kind": {
			enableExtensionRefFilters: true,
			namespace:                 "default",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("cilium.io"),
				Kind:  gatewayv1.Kind("WrongKind"),
				Name:  "my-ext-proc",
			},
			expectedFilter: nil,
			expectedOK:     false,
		},
		"CRD not found": {
			enableExtensionRefFilters: true,
			namespace:                 "default",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("cilium.io"),
				Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
				Name:  "nonexistent",
			},
			expectedFilter: nil,
			expectedOK:     false,
		},
		"wrong namespace": {
			enableExtensionRefFilters: true,
			namespace:                 "kube-system",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("cilium.io"),
				Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
				Name:  "my-ext-proc",
			},
			expectedFilter: nil,
			expectedOK:     false,
		},
		"success": {
			enableExtensionRefFilters: true,
			namespace:                 "default",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("cilium.io"),
				Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
				Name:  "my-ext-proc",
			},
			expectedOK: true,
		},
		"success with cross-namespace backendRef": {
			enableExtensionRefFilters: true,
			namespace:                 "default",
			ref: &gatewayv1.LocalObjectReference{
				Group: gatewayv1.Group("cilium.io"),
				Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
				Name:  "cross-ns-ext-proc",
			},
			expectedOK: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
			filter, ok := resolveExtensionRef(logger, tc.enableExtensionRefFilters, tc.namespace, tc.ref, extProcFilters)
			assert.Equal(t, tc.expectedOK, ok)

			if !tc.expectedOK {
				assert.Nil(t, filter)
				return
			}

			require.NotNil(t, filter)
			assert.Equal(t, model.ExtProcExternalProcessorTypeURL, filter.TypeURL)
			require.NotNil(t, filter.Backend)

			if name == "success" {
				assert.Equal(t, "envoy.filters.http.ext_proc/default/my-ext-proc", filter.Name)
				assert.Equal(t, "ext-proc-service", filter.Backend.Name)
				assert.Equal(t, "default", filter.Backend.Namespace)
				require.NotNil(t, filter.Backend.Port)
				assert.Equal(t, uint32(9001), filter.Backend.Port.Port)
			}

			if name == "success with cross-namespace backendRef" {
				assert.Equal(t, "envoy.filters.http.ext_proc/default/cross-ns-ext-proc", filter.Name)
				assert.Equal(t, "ext-proc-service", filter.Backend.Name)
				assert.Equal(t, "other-namespace", filter.Backend.Namespace)
				require.NotNil(t, filter.Backend.Port)
				assert.Equal(t, uint32(9002), filter.Backend.Port.Port)
			}
		})
	}
}

func Test_crdToExtensionRefFilter(t *testing.T) {
	tests := map[string]struct {
		crd       *v2alpha1.CiliumEnvoyExtProcFilter
		checkFunc func(t *testing.T, filter *model.ExtensionRefFilter)
		expectOK  bool
	}{
		"basic": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "basic-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "my-grpc-service",
						Port: 50051,
					},
				},
			},
			expectOK: true,
			checkFunc: func(t *testing.T, filter *model.ExtensionRefFilter) {
				assert.Equal(t, "envoy.filters.http.ext_proc/default/basic-filter", filter.Name)
				assert.Equal(t, model.ExtProcExternalProcessorTypeURL, filter.TypeURL)

				require.NotNil(t, filter.Backend)
				assert.Equal(t, "my-grpc-service", filter.Backend.Name)
				assert.Equal(t, "default", filter.Backend.Namespace)
				require.NotNil(t, filter.Backend.Port)
				assert.Equal(t, uint32(50051), filter.Backend.Port.Port)

				// Verify the protobuf config unmarshals correctly
				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				require.NotNil(t, extProc.GrpcService)
				require.NotNil(t, extProc.GrpcService.GetEnvoyGrpc())
				assert.Equal(t, "default:my-grpc-service:50051", extProc.GrpcService.GetEnvoyGrpc().ClusterName)
				assert.Equal(t, "my-grpc-service:50051", extProc.GrpcService.GetEnvoyGrpc().Authority)
				assert.Equal(t, "ceepf.default.basic_filter.", extProc.StatPrefix)
			},
		},
		"with processing mode": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "proc-mode-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "ext-proc-svc",
						Port: 50051,
					},
					ProcessingMode: &v2alpha1.ExtProcProcessingMode{
						RequestHeaderMode:  ptr.To("SEND"),
						ResponseHeaderMode: ptr.To("SKIP"),
						RequestBodyMode:    ptr.To("BUFFERED"),
						ResponseBodyMode:   ptr.To("STREAMED"),
					},
				},
			},
			expectOK: true,
			checkFunc: func(t *testing.T, filter *model.ExtensionRefFilter) {
				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				require.NotNil(t, extProc.ProcessingMode)
				assert.Equal(t, ext_procv3.ProcessingMode_SEND, extProc.ProcessingMode.RequestHeaderMode)
				assert.Equal(t, ext_procv3.ProcessingMode_SKIP, extProc.ProcessingMode.ResponseHeaderMode)
				assert.Equal(t, ext_procv3.ProcessingMode_BUFFERED, extProc.ProcessingMode.RequestBodyMode)
				assert.Equal(t, ext_procv3.ProcessingMode_STREAMED, extProc.ProcessingMode.ResponseBodyMode)
			},
		},
		"with message timeout": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "timeout-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "ext-proc-svc",
						Port: 50051,
					},
					MessageTimeout: &v2alpha1.ExtProcMessageTimeout{Duration: 10 * time.Second},
				},
			},
			expectOK: true,
			checkFunc: func(t *testing.T, filter *model.ExtensionRefFilter) {
				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				require.NotNil(t, extProc.MessageTimeout)
				assert.Equal(t, 10*time.Second, extProc.MessageTimeout.AsDuration())
			},
		},
		"with failure mode allow": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "failure-mode-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "ext-proc-svc",
						Port: 50051,
					},
					FailureModeAllow: true,
				},
			},
			expectOK: true,
			checkFunc: func(t *testing.T, filter *model.ExtensionRefFilter) {
				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				assert.True(t, extProc.FailureModeAllow)
			},
		},
		"cross-namespace backendRef": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cross-ns-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name:      "ext-proc-svc",
						Namespace: ptr.To("other-namespace"),
						Port:      50051,
					},
				},
			},
			expectOK: true,
			checkFunc: func(t *testing.T, filter *model.ExtensionRefFilter) {
				assert.Equal(t, "envoy.filters.http.ext_proc/default/cross-ns-filter", filter.Name)
				require.NotNil(t, filter.Backend)
				assert.Equal(t, "ext-proc-svc", filter.Backend.Name)
				assert.Equal(t, "other-namespace", filter.Backend.Namespace)

				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				require.NotNil(t, extProc.GrpcService)
				require.NotNil(t, extProc.GrpcService.GetEnvoyGrpc())
				assert.Equal(t, "other-namespace:ext-proc-svc:50051", extProc.GrpcService.GetEnvoyGrpc().ClusterName)
				assert.Equal(t, "ext-proc-svc:50051", extProc.GrpcService.GetEnvoyGrpc().Authority)
				assert.Equal(t, "ceepf.default.cross_ns_filter.", extProc.StatPrefix)
			},
		},
		"stat prefix sanitizes resource identity": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "dotted.ext-proc-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "ext-proc-svc",
						Port: 50051,
					},
				},
			},
			expectOK: true,
			checkFunc: func(t *testing.T, filter *model.ExtensionRefFilter) {
				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				assert.Equal(t, "ceepf.default.dotted_ext_proc_filter.", extProc.StatPrefix)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
			filter, ok := crdToExtensionRefFilter(logger, tc.crd)
			assert.Equal(t, tc.expectOK, ok)

			if !tc.expectOK {
				assert.Nil(t, filter)
				return
			}

			require.NotNil(t, filter)
			tc.checkFunc(t, filter)
		})
	}
}

func Test_convertProcessingMode(t *testing.T) {
	tests := map[string]struct {
		input    *v2alpha1.ExtProcProcessingMode
		expected *ext_procv3.ProcessingMode
	}{
		"nil fields": {
			input:    &v2alpha1.ExtProcProcessingMode{},
			expected: &ext_procv3.ProcessingMode{},
		},
		"all fields set": {
			input: &v2alpha1.ExtProcProcessingMode{
				RequestHeaderMode:   ptr.To("SEND"),
				ResponseHeaderMode:  ptr.To("SKIP"),
				RequestBodyMode:     ptr.To("BUFFERED"),
				ResponseBodyMode:    ptr.To("STREAMED"),
				RequestTrailerMode:  ptr.To("SEND"),
				ResponseTrailerMode: ptr.To("SKIP"),
			},
			expected: &ext_procv3.ProcessingMode{
				RequestHeaderMode:   ext_procv3.ProcessingMode_SEND,
				ResponseHeaderMode:  ext_procv3.ProcessingMode_SKIP,
				RequestBodyMode:     ext_procv3.ProcessingMode_BUFFERED,
				ResponseBodyMode:    ext_procv3.ProcessingMode_STREAMED,
				RequestTrailerMode:  ext_procv3.ProcessingMode_SEND,
				ResponseTrailerMode: ext_procv3.ProcessingMode_SKIP,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := convertProcessingMode(tc.input)
			assert.Equal(t, tc.expected.RequestHeaderMode, result.RequestHeaderMode)
			assert.Equal(t, tc.expected.ResponseHeaderMode, result.ResponseHeaderMode)
			assert.Equal(t, tc.expected.RequestBodyMode, result.RequestBodyMode)
			assert.Equal(t, tc.expected.ResponseBodyMode, result.ResponseBodyMode)
			assert.Equal(t, tc.expected.RequestTrailerMode, result.RequestTrailerMode)
			assert.Equal(t, tc.expected.ResponseTrailerMode, result.ResponseTrailerMode)
		})
	}
}

func Test_toHeaderSendMode(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected ext_procv3.ProcessingMode_HeaderSendMode
	}{
		"SEND": {
			input:    "SEND",
			expected: ext_procv3.ProcessingMode_SEND,
		},
		"SKIP": {
			input:    "SKIP",
			expected: ext_procv3.ProcessingMode_SKIP,
		},
		"DEFAULT": {
			input:    "DEFAULT",
			expected: ext_procv3.ProcessingMode_DEFAULT,
		},
		"unknown": {
			input:    "something-else",
			expected: ext_procv3.ProcessingMode_DEFAULT,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := toHeaderSendMode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func Test_toBodySendMode(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected ext_procv3.ProcessingMode_BodySendMode
	}{
		"NONE": {
			input:    "NONE",
			expected: ext_procv3.ProcessingMode_NONE,
		},
		"STREAMED": {
			input:    "STREAMED",
			expected: ext_procv3.ProcessingMode_STREAMED,
		},
		"BUFFERED": {
			input:    "BUFFERED",
			expected: ext_procv3.ProcessingMode_BUFFERED,
		},
		"BUFFERED_PARTIAL": {
			input:    "BUFFERED_PARTIAL",
			expected: ext_procv3.ProcessingMode_BUFFERED_PARTIAL,
		},
		"unknown": {
			input:    "something-else",
			expected: ext_procv3.ProcessingMode_NONE,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := toBodySendMode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func Test_extractRoutes_multipleExtensionRefFilters(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	extProcFilters := []v2alpha1.CiliumEnvoyExtProcFilter{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "filter-a",
				Namespace: "default",
			},
			Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
				BackendRef: v2alpha1.ExtProcBackendRef{
					Name: "svc-a",
					Port: 9001,
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "filter-b",
				Namespace: "default",
			},
			Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
				BackendRef: v2alpha1.ExtProcBackendRef{
					Name: "svc-b",
					Port: 9002,
				},
			},
		},
	}

	t.Run("two extension ref filters preserved in declaration order", func(t *testing.T) {
		hr := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Filters: []gatewayv1.HTTPRouteFilter{
							{
								Type: gatewayv1.HTTPRouteFilterExtensionRef,
								ExtensionRef: &gatewayv1.LocalObjectReference{
									Group: gatewayv1.Group("cilium.io"),
									Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
									Name:  "filter-a",
								},
							},
							{
								Type: gatewayv1.HTTPRouteFilterExtensionRef,
								ExtensionRef: &gatewayv1.LocalObjectReference{
									Group: gatewayv1.Group("cilium.io"),
									Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
									Name:  "filter-b",
								},
							},
						},
					},
				},
			},
		}

		routes := extractRoutes(logger, 80, []string{"*"}, hr, nil, nil, nil, nil, true, extProcFilters)
		require.Len(t, routes, 1)
		assert.Len(t, routes[0].ExtensionRefFilters, 2)
		assert.Equal(t, "envoy.filters.http.ext_proc/default/filter-a", routes[0].ExtensionRefFilters[0].Name)
		assert.Equal(t, "envoy.filters.http.ext_proc/default/filter-b", routes[0].ExtensionRefFilters[1].Name)
	})

	t.Run("invalid extension ref clears all filters and produces 500 response", func(t *testing.T) {
		hr := gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-route",
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				Rules: []gatewayv1.HTTPRouteRule{
					{
						Filters: []gatewayv1.HTTPRouteFilter{
							{
								Type: gatewayv1.HTTPRouteFilterExtensionRef,
								ExtensionRef: &gatewayv1.LocalObjectReference{
									Group: gatewayv1.Group("cilium.io"),
									Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
									Name:  "filter-a",
								},
							},
							{
								Type: gatewayv1.HTTPRouteFilterExtensionRef,
								ExtensionRef: &gatewayv1.LocalObjectReference{
									Group: gatewayv1.Group("cilium.io"),
									Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
									Name:  "nonexistent",
								},
							},
						},
					},
				},
			},
		}

		routes := extractRoutes(logger, 80, []string{"*"}, hr, nil, nil, nil, nil, true, extProcFilters)
		require.Len(t, routes, 1)
		assert.Empty(t, routes[0].ExtensionRefFilters)
		require.NotNil(t, routes[0].DirectResponse)
		assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	})
}
