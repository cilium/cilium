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
	corev1 "k8s.io/api/core/v1"
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
				assert.Equal(t, "ext-proc-service", filter.Backend.Name)
				assert.Equal(t, "default", filter.Backend.Namespace)
				require.NotNil(t, filter.Backend.Port)
				assert.Equal(t, uint32(9001), filter.Backend.Port.Port)
			}

			if name == "success with cross-namespace backendRef" {
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
				assert.False(t, extProc.GetFailureModeAllow())
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
						RequestHeaderMode:  ptr.To(v2alpha1.ExtProcHeaderModeSend),
						ResponseHeaderMode: ptr.To(v2alpha1.ExtProcHeaderModeSkip),
						RequestBodyMode:    ptr.To(v2alpha1.ExtProcBodyModeBuffered),
						ResponseBodyMode:   ptr.To(v2alpha1.ExtProcBodyModeStreamed),
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
		"message timeout above Envoy maximum": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-timeout-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "ext-proc-svc",
						Port: 50051,
					},
					MessageTimeout: &v2alpha1.ExtProcMessageTimeout{Duration: time.Hour + time.Nanosecond},
				},
			},
			expectOK: false,
		},
		"message timeout negative": {
			crd: &v2alpha1.CiliumEnvoyExtProcFilter{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "negative-timeout-filter",
					Namespace: "default",
				},
				Spec: v2alpha1.CiliumEnvoyExtProcFilterSpec{
					BackendRef: v2alpha1.ExtProcBackendRef{
						Name: "ext-proc-svc",
						Port: 50051,
					},
					MessageTimeout: &v2alpha1.ExtProcMessageTimeout{Duration: -1 * time.Second},
				},
			},
			expectOK: false,
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
				require.NotNil(t, filter.Backend)
				assert.Equal(t, "ext-proc-svc", filter.Backend.Name)
				assert.Equal(t, "other-namespace", filter.Backend.Namespace)

				extProc := &ext_procv3.ExternalProcessor{}
				require.NoError(t, proto.Unmarshal(filter.Config, extProc))
				require.NotNil(t, extProc.GrpcService)
				require.NotNil(t, extProc.GrpcService.GetEnvoyGrpc())
				assert.Equal(t, "other-namespace:ext-proc-svc:50051", extProc.GrpcService.GetEnvoyGrpc().ClusterName)
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
				RequestHeaderMode:   ptr.To(v2alpha1.ExtProcHeaderModeSend),
				ResponseHeaderMode:  ptr.To(v2alpha1.ExtProcHeaderModeSkip),
				RequestBodyMode:     ptr.To(v2alpha1.ExtProcBodyModeBuffered),
				ResponseBodyMode:    ptr.To(v2alpha1.ExtProcBodyModeStreamed),
				RequestTrailerMode:  ptr.To(v2alpha1.ExtProcHeaderModeSend),
				ResponseTrailerMode: ptr.To(v2alpha1.ExtProcHeaderModeSkip),
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
		input    v2alpha1.ExtProcHeaderMode
		expected ext_procv3.ProcessingMode_HeaderSendMode
	}{
		"SEND": {
			input:    v2alpha1.ExtProcHeaderModeSend,
			expected: ext_procv3.ProcessingMode_SEND,
		},
		"SKIP": {
			input:    v2alpha1.ExtProcHeaderModeSkip,
			expected: ext_procv3.ProcessingMode_SKIP,
		},
		"DEFAULT": {
			input:    v2alpha1.ExtProcHeaderMode("DEFAULT"),
			expected: ext_procv3.ProcessingMode_DEFAULT,
		},
		"unknown": {
			input:    v2alpha1.ExtProcHeaderMode("something-else"),
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
		input    v2alpha1.ExtProcBodyMode
		expected ext_procv3.ProcessingMode_BodySendMode
	}{
		"NONE": {
			input:    v2alpha1.ExtProcBodyModeNone,
			expected: ext_procv3.ProcessingMode_NONE,
		},
		"STREAMED": {
			input:    v2alpha1.ExtProcBodyModeStreamed,
			expected: ext_procv3.ProcessingMode_STREAMED,
		},
		"BUFFERED": {
			input:    v2alpha1.ExtProcBodyModeBuffered,
			expected: ext_procv3.ProcessingMode_BUFFERED,
		},
		"BUFFERED_PARTIAL": {
			input:    v2alpha1.ExtProcBodyModeBufferedPartial,
			expected: ext_procv3.ProcessingMode_BUFFERED_PARTIAL,
		},
		"unknown": {
			input:    v2alpha1.ExtProcBodyMode("something-else"),
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

func Test_extractRoutes_invalidExtensionRefPreservesValidExternalAuth(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	hr := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-ext-proc-with-auth",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend",
									Port: ptr.To(gatewayv1.PortNumber(8080)),
								},
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{
						{
							Type: gatewayv1.HTTPRouteFilterExternalAuth,
							ExternalAuth: &gatewayv1.HTTPExternalAuthFilter{
								BackendRef: gatewayv1.BackendObjectReference{
									Name: "auth-backend",
									Port: ptr.To(gatewayv1.PortNumber(9000)),
								},
							},
						},
						{
							Type: gatewayv1.HTTPRouteFilterExtensionRef,
							ExtensionRef: &gatewayv1.LocalObjectReference{
								Group: gatewayv1.Group("cilium.io"),
								Kind:  gatewayv1.Kind("CiliumEnvoyExtProcFilter"),
								Name:  "missing-ext-proc",
							},
						},
					},
				},
			},
		},
	}

	routes := extractRoutes(logger, 80, []string{"*"}, hr, []corev1.Service{
		testService("default", "backend", 8080),
		testService("default", "auth-backend", 9000),
	}, nil, nil, nil, true, nil)

	require.Len(t, routes, 1)
	require.NotNil(t, routes[0].DirectResponse)
	assert.Equal(t, 500, routes[0].DirectResponse.StatusCode)
	assert.Nil(t, routes[0].Backends)
	assert.Nil(t, routes[0].ExtensionRefFilters)
	require.NotNil(t, routes[0].ExternalAuth)
	assert.Equal(t, "auth-backend", routes[0].ExternalAuth.Backend.Name)
	assert.Equal(t, "default", routes[0].ExternalAuth.Backend.Namespace)
	assert.Equal(t, uint32(9000), routes[0].ExternalAuth.Backend.Port.Port)
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
						BackendRefs: []gatewayv1.HTTPBackendRef{
							{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: "backend",
										Port: ptr.To(gatewayv1.PortNumber(8080)),
									},
								},
							},
						},
					},
				},
			},
		}

		services := []corev1.Service{testService("default", "backend", 8080)}
		routes := extractRoutes(logger, 80, []string{"*"}, hr, services, nil, nil, nil, true, extProcFilters)
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
