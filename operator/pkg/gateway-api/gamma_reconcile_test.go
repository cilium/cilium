// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8stestutils "github.com/cilium/cilium/pkg/k8s/testutils"
)

var cmpIgnoreFields = []cmp.Option{
	cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime"),
	cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ResourceVersion", "CreationTimestamp"),
}

var (
	serviceKeyEcho   = types.NamespacedName{Namespace: "gateway-conformance-mesh", Name: "echo"}
	serviceKeyEchoV1 = types.NamespacedName{Namespace: "gateway-conformance-mesh", Name: "echo-v1"}
	serviceKeyEchoV2 = types.NamespacedName{Namespace: "gateway-conformance-mesh", Name: "echo-v2"}
)

func Test_gammaReconciler_Reconcile(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})
	cecTranslatorWithProxy := translation.NewCECTranslator(translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			UseProxyProtocol:         true,
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})

	tests := []struct {
		name          string
		serviceKey    []types.NamespacedName
		wantErr       bool
		proxyProtocol bool
	}{
		{name: "mesh-basic", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-proxy-protocol", serviceKey: []types.NamespacedName{serviceKeyEcho}, proxyProtocol: true},
		{name: "mesh-split", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-frontend", serviceKey: []types.NamespacedName{serviceKeyEchoV2}},
		{name: "mesh-matching", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-ports", serviceKey: []types.NamespacedName{serviceKeyEchoV1, serviceKeyEchoV2}},
		{name: "mesh-query-param-matching", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-host-and-status", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-path", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-port", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-redirect-scheme", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-request-header-modifier", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-rewrite-path", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-weighted-backends", serviceKey: []types.NamespacedName{serviceKeyEcho}},
		{name: "mesh-grpc-weight", serviceKey: []types.NamespacedName{serviceKeyEcho}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, serviceKey := range tt.serviceKey {
				t.Run(serviceKey.String(), func(t *testing.T) {
					scheme := testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)
					base := k8stestutils.ReadObjectsDir(t, "testdata/gamma/base", scheme)
					input := k8stestutils.ReadObjectsDir(t, fmt.Sprintf("testdata/gamma/%s/input", tt.name), scheme)

					c := fake.NewClientBuilder().
						WithScheme(scheme).
						WithObjects(append(base, input...)...).
						WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
						WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
						WithStatusSubresource(&corev1.Service{}).
						WithStatusSubresource(&gatewayv1.HTTPRoute{}).
						WithStatusSubresource(&gatewayv1.GRPCRoute{}).
						WithInterceptorFuncs(typeMetaInterceptor(scheme)).
						Build()

					selectedCECTranslator := cecTranslator
					if tt.proxyProtocol {
						selectedCECTranslator = cecTranslatorWithProxy
					}
					gatewayAPITranslator := gatewayApiTranslation.NewTranslator(selectedCECTranslator, translation.Config{
						ServiceConfig: translation.ServiceConfig{
							ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
						},
						OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
							UseRemoteAddress: true,
						},
					})

					r := &gammaReconciler{
						client:         c,
						translator:     gatewayAPITranslator,
						logger:         logger,
						controllerName: defaultControllerName,
					}

					// Reconcile all related HTTPRoute objects
					hrList := &gatewayv1.HTTPRouteList{}
					err := c.List(t.Context(), hrList)
					require.NoError(t, err)
					filterHTTPRouteList := filterHTTPRoute(hrList, serviceKey.Name, serviceKey.Namespace)

					// Reconcile all related GRPCRoute objects
					grpcrList := &gatewayv1.GRPCRouteList{}
					err = c.List(t.Context(), grpcrList)
					require.NoError(t, err)
					filterGRPCRouteList := filterGRPCRoute(grpcrList, serviceKey.Name, serviceKey.Namespace)

					t.Logf("Test %s, HTTPRoutes: %d, GRPCRoutes: %d", tt.name, len(filterHTTPRouteList), len(filterGRPCRouteList))
					result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKey})
					require.Equal(t, tt.wantErr, err != nil, "Error mismatch, error was %s", err)
					require.Equal(t, ctrl.Result{}, result)

					// Checking the output for Service
					expectedService := &corev1.Service{}
					k8stestutils.ReadYAML(t, fmt.Sprintf("testdata/gamma/%s/output/service-%s.yaml", tt.name, serviceKey.Name), expectedService)
					actualService := &corev1.Service{}
					err = c.Get(t.Context(), serviceKey, actualService)
					require.NoError(t, err)

					for _, hr := range filterHTTPRouteList {
						actualHR := &gatewayv1.HTTPRoute{}
						err = c.Get(t.Context(), client.ObjectKeyFromObject(&hr), actualHR)
						require.NoError(t, err, "error getting HTTPRoute %s/%s: %v", hr.Namespace, hr.Name, err)
						expectedHR := &gatewayv1.HTTPRoute{}
						k8stestutils.ReadYAML(t, fmt.Sprintf("testdata/gamma/%s/output/httproute-%s.yaml", tt.name, hr.Name), expectedHR)
						require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))
					}

					for _, grpcr := range filterGRPCRouteList {
						actualGRPCR := &gatewayv1.GRPCRoute{}
						err = c.Get(t.Context(), client.ObjectKeyFromObject(&grpcr), actualGRPCR)
						require.NoError(t, err, "error getting GRPCRoute %s/%s: %v", grpcr.Namespace, grpcr.Name, err)
						expectedGRPCR := &gatewayv1.GRPCRoute{}
						k8stestutils.ReadYAML(t, fmt.Sprintf("testdata/gamma/%s/output/grpcroute-%s.yaml", tt.name, grpcr.Name), expectedGRPCR)
						require.Empty(t, cmp.Diff(expectedGRPCR, actualGRPCR, cmpIgnoreFields...))
					}

					if !tt.wantErr {
						// Checking the output for CiliumEnvoyConfig
						actualCEC := &ciliumv2.CiliumEnvoyConfig{}
						err = c.Get(t.Context(), serviceKey, actualCEC)
						require.NoError(t, err, "Could not get CiliumEnvoyConfig and wasn't expecting a reconciliation error")
						expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
						k8stestutils.ReadYAML(t, fmt.Sprintf("testdata/gamma/%s/output/cec-%s.yaml", tt.name, serviceKey.Name), expectedCEC)

						require.NoError(t, err)
						require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
					}
				})
			}
		})
	}
}

func Test_gammaReconciler_Reconcile_BackendRequestHeaderModifier(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})

	scheme := testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)
	base := k8stestutils.ReadObjectsDir(t, "testdata/gamma/base", scheme)
	input := k8stestutils.ReadObjectsDir(t, "testdata/gamma/mesh-request-header-modifier-backend/input", scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(append(base, input...)...).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
		WithStatusSubresource(&corev1.Service{}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		WithStatusSubresource(&gatewayv1.GRPCRoute{}).
		WithInterceptorFuncs(typeMetaInterceptor(scheme)).
		Build()

	r := &gammaReconciler{
		client:         c,
		translator:     gatewayAPITranslator,
		logger:         logger,
		controllerName: defaultControllerName,
	}

	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	actualCEC := &ciliumv2.CiliumEnvoyConfig{}
	err = c.Get(t.Context(), serviceKeyEcho, actualCEC)
	require.NoError(t, err)

	cecYAML := k8stestutils.ToYAML(t, actualCEC)
	for _, want := range []string{
		"requestHeadersToAdd:",
		"key: X-Header-Set",
		"value: set-overwrites-values",
		"key: X-Header-Add",
		"value: add-appends-values",
		"requestHeadersToRemove:",
		"- X-Header-Remove",
	} {
		assert.Contains(t, cecYAML, want)
	}

	actualHR := &gatewayv1.HTTPRoute{}
	err = c.Get(t.Context(), types.NamespacedName{
		Namespace: "gateway-conformance-mesh",
		Name:      "mesh-request-header-modifier",
	}, actualHR)
	require.NoError(t, err)

	hrYAML := k8stestutils.ToYAML(t, actualHR)
	assert.True(t, strings.Contains(hrYAML, "filters:") || strings.Contains(hrYAML, "requestHeaderModifier:"))
}

func Test_gammaReconciler_Reconcile_ReplacesOwnerReferencesForRecreatedRoute(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})

	scheme := testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)
	base := k8stestutils.ReadObjectsDir(t, "testdata/gamma/base", scheme)
	originalInput := k8stestutils.ReadObjectsDir(t, "testdata/gamma/mesh-request-header-modifier/input", scheme)
	recreatedInput := k8stestutils.ReadObjectsDir(t, "testdata/gamma/mesh-request-header-modifier-backend/input", scheme)

	setRouteIdentity := func(objs []client.Object, uid string) {
		t.Helper()

		for _, obj := range objs {
			hr, ok := obj.(*gatewayv1.HTTPRoute)
			if !ok {
				continue
			}
			if hr.Name != "mesh-request-header-modifier" || hr.Namespace != "gateway-conformance-mesh" {
				continue
			}
			hr.SetUID(types.UID(uid))
			hr.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   gatewayv1.GroupVersion.Group,
				Version: gatewayv1.GroupVersion.Version,
				Kind:    "HTTPRoute",
			})
		}
	}

	setRouteIdentity(originalInput, "old-route-uid")
	setRouteIdentity(recreatedInput, "new-route-uid")

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(base...).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
		WithStatusSubresource(&corev1.Service{}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		WithStatusSubresource(&gatewayv1.GRPCRoute{}).
		WithInterceptorFuncs(typeMetaInterceptor(scheme)).
		Build()

	r := &gammaReconciler{
		client:         c,
		translator:     gatewayAPITranslator,
		logger:         logger,
		controllerName: defaultControllerName,
	}

	for _, obj := range originalInput {
		require.NoError(t, c.Create(t.Context(), obj.DeepCopyObject().(client.Object)))
	}

	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	actualCEC := &ciliumv2.CiliumEnvoyConfig{}
	err = c.Get(t.Context(), serviceKeyEcho, actualCEC)
	require.NoError(t, err)
	require.Len(t, actualCEC.OwnerReferences, 1)
	assert.Equal(t, "old-route-uid", string(actualCEC.OwnerReferences[0].UID))

	originalRoute := &gatewayv1.HTTPRoute{}
	err = c.Get(t.Context(), types.NamespacedName{
		Namespace: "gateway-conformance-mesh",
		Name:      "mesh-request-header-modifier",
	}, originalRoute)
	require.NoError(t, err)
	require.NoError(t, c.Delete(t.Context(), originalRoute))

	for _, obj := range recreatedInput {
		require.NoError(t, c.Create(t.Context(), obj.DeepCopyObject().(client.Object)))
	}

	result, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	err = c.Get(t.Context(), serviceKeyEcho, actualCEC)
	require.NoError(t, err)
	require.Len(t, actualCEC.OwnerReferences, 1)
	assert.Equal(t, "new-route-uid", string(actualCEC.OwnerReferences[0].UID))
}

func Test_gammaReconciler_Reconcile_DeletesEnvoyConfigWhenRouteDetachesFromService(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		RouteConfig:               translation.RouteConfig{HostNameSuffixMatch: true},
		ListenerConfig:            translation.ListenerConfig{StreamIdleTimeoutSeconds: 300},
		ClusterConfig:             translation.ClusterConfig{IdleTimeoutSeconds: 60},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{UseRemoteAddress: true},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig:             translation.ServiceConfig{ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster)},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{UseRemoteAddress: true},
	})

	scheme := testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)
	base := k8stestutils.ReadObjectsDir(t, "testdata/gamma/base", scheme)
	input := k8stestutils.ReadObjectsDir(t, "testdata/gamma/mesh-request-header-modifier/input", scheme)

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(append(base, input...)...).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
		WithStatusSubresource(&corev1.Service{}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		WithStatusSubresource(&gatewayv1.GRPCRoute{}).
		WithInterceptorFuncs(typeMetaInterceptor(scheme)).
		Build()

	r := &gammaReconciler{
		client:         c,
		translator:     gatewayAPITranslator,
		logger:         logger,
		controllerName: defaultControllerName,
	}

	// The Service starts out as a GAMMA Service, so the reconciler generates a CEC for it.
	result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	cec := &ciliumv2.CiliumEnvoyConfig{}
	require.NoError(t, c.Get(t.Context(), serviceKeyEcho, cec))

	eps := &discoveryv1.EndpointSlice{}
	epsKey := types.NamespacedName{
		Namespace: serviceKeyEcho.Namespace,
		Name:      gatewayApiTranslation.CiliumGatewayPrefix + serviceKeyEcho.Name,
	}
	require.NoError(t, c.Get(t.Context(), epsKey, eps))

	// Re-parent the same HTTPRoute object from the Service to a Gateway. The Service
	// is then no longer the parent of any GAMMA route.
	route := &gatewayv1.HTTPRoute{}
	require.NoError(t, c.Get(t.Context(), types.NamespacedName{
		Namespace: "gateway-conformance-mesh",
		Name:      "mesh-request-header-modifier",
	}, route))

	gwGroup := gatewayv1.Group(gatewayv1.GroupVersion.Group)
	gwKind := gatewayv1.Kind("Gateway")
	route.Spec.ParentRefs = []gatewayv1.ParentReference{{
		Group: &gwGroup,
		Kind:  &gwKind,
		Name:  gatewayv1.ObjectName("my-gateway"),
	}}
	require.NoError(t, c.Update(t.Context(), route))

	result, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, result)

	// The CEC generated while the Service was a GAMMA Service must be gone.
	err = c.Get(t.Context(), serviceKeyEcho, cec)
	require.True(t, k8serrors.IsNotFound(err), "expected CiliumEnvoyConfig to be deleted, got %v", err)

	err = c.Get(t.Context(), epsKey, eps)
	require.True(t, k8serrors.IsNotFound(err), "expected EndpointSlice to be deleted, got %v", err)
}

func Test_gammaReconciler_Reconcile_KeepsUnrelatedEnvoyConfigWhenRouteDetaches(t *testing.T) {
	// Each case is a CiliumEnvoyConfig that shares the Service's name but was not
	// generated by the GAMMA reconciler, and so must survive the cleanup. The
	// three cases cover the three ways isGammaOwnedEnvoyConfig can reject an object.
	tests := map[string][]metav1.OwnerReference{
		"no controller at all": nil,
		"controlled by something outside the Gateway API group": {{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       "echo",
			UID:        types.UID("deployment-uid"),
			Controller: ptr.To(true),
		}},
		"controlled by a Gateway rather than a route": {{
			APIVersion: gatewayv1.GroupVersion.String(),
			Kind:       "Gateway",
			Name:       "my-gateway",
			UID:        types.UID("gateway-uid"),
			Controller: ptr.To(true),
		}},
	}

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
		RouteConfig:               translation.RouteConfig{HostNameSuffixMatch: true},
		ListenerConfig:            translation.ListenerConfig{StreamIdleTimeoutSeconds: 300},
		ClusterConfig:             translation.ClusterConfig{IdleTimeoutSeconds: 60},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{UseRemoteAddress: true},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig:             translation.ServiceConfig{ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster)},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{UseRemoteAddress: true},
	})
	scheme := testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)

	for name, ownerRefs := range tests {
		t.Run(name, func(t *testing.T) {
			base := k8stestutils.ReadObjectsDir(t, "testdata/gamma/base", scheme)
			unrelated := &ciliumv2.CiliumEnvoyConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:            serviceKeyEcho.Name,
					Namespace:       serviceKeyEcho.Namespace,
					OwnerReferences: ownerRefs,
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(append(base, unrelated)...).
				WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
				WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
				WithStatusSubresource(&corev1.Service{}).
				WithStatusSubresource(&gatewayv1.HTTPRoute{}).
				WithStatusSubresource(&gatewayv1.GRPCRoute{}).
				WithInterceptorFuncs(typeMetaInterceptor(scheme)).
				Build()

			r := &gammaReconciler{
				client:         c,
				translator:     gatewayAPITranslator,
				logger:         logger,
				controllerName: defaultControllerName,
			}

			// No GAMMA route references the Service, so the cleanup path runs.
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: serviceKeyEcho})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)

			require.NoError(t, c.Get(t.Context(), serviceKeyEcho, &ciliumv2.CiliumEnvoyConfig{}),
				"a CiliumEnvoyConfig not controlled by a Gateway API route must not be deleted")
		})
	}
}
