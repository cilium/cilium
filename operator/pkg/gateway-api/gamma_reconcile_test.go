// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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

func Test_gammaReconciler_Reconcile_RouteOrdering(t *testing.T) {
	for _, tt := range []struct {
		kind string
		port gatewayv1.PortNumber
	}{
		{kind: "HTTPRoute", port: 80},
		{kind: "GRPCRoute", port: 7070},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			logger := hivetest.Logger(t)
			scheme := testhelpers.TestScheme(nil, helpers.RegisterGatewayAPITypesToScheme)
			objects := k8stestutils.ReadObjectsDir(t, "testdata/gamma/base", scheme)
			var routes []client.Object
			for i, name := range []string{"older", "newer"} {
				objectMeta := metav1.ObjectMeta{
					Name:              name,
					Namespace:         serviceKeyEcho.Namespace,
					UID:               types.UID(name + "-uid"),
					CreationTimestamp: metav1.Unix(1700000000+int64(i), 0),
				}
				parents := gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{
						Group: ptr.To[gatewayv1.Group](""),
						Kind:  ptr.To[gatewayv1.Kind]("Service"),
						Name:  gatewayv1.ObjectName(serviceKeyEcho.Name),
						Port:  ptr.To(tt.port),
					}},
				}
				backend := gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: "echo-v1",
						Port: ptr.To(tt.port),
					},
				}
				switch tt.kind {
				case "HTTPRoute":
					routes = append(routes, &gatewayv1.HTTPRoute{
						ObjectMeta: objectMeta,
						Spec: gatewayv1.HTTPRouteSpec{
							CommonRouteSpec: parents,
							Rules: []gatewayv1.HTTPRouteRule{{
								Matches: []gatewayv1.HTTPRouteMatch{{
									Path: &gatewayv1.HTTPPathMatch{
										Type:  ptr.To(gatewayv1.PathMatchExact),
										Value: ptr.To(fmt.Sprintf("/method-%d", i)),
									},
								}},
								BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: backend}},
							}},
						},
					})
				case "GRPCRoute":
					routes = append(routes, &gatewayv1.GRPCRoute{
						ObjectMeta: objectMeta,
						Spec: gatewayv1.GRPCRouteSpec{
							CommonRouteSpec: parents,
							Rules: []gatewayv1.GRPCRouteRule{{
								Matches: []gatewayv1.GRPCRouteMatch{{
									Method: &gatewayv1.GRPCMethodMatch{
										Type:    ptr.To(gatewayv1.GRPCMethodMatchExact),
										Service: ptr.To("example.Echo"),
										Method:  ptr.To(fmt.Sprintf("Method%d", i)),
									},
								}},
								BackendRefs: []gatewayv1.GRPCBackendRef{{BackendRef: backend}},
							}},
						},
					})
				}
			}
			objects = append(objects, routes...)

			funcs := typeMetaInterceptor(scheme)
			list := funcs.List
			reverseRouteOrder := false
			var routeOrders [][]string
			cecPatches := 0
			funcs.List = func(ctx context.Context, c client.WithWatch, obj client.ObjectList, opts ...client.ListOption) error {
				if err := list(ctx, c, obj, opts...); err != nil {
					return err
				}
				switch routeList := obj.(type) {
				case *gatewayv1.HTTPRouteList:
					if tt.kind != "HTTPRoute" {
						return nil
					}
					require.Len(t, routeList.Items, 2)
					slices.SortFunc(routeList.Items, func(a, b gatewayv1.HTTPRoute) int {
						return a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time)
					})
					if reverseRouteOrder {
						slices.Reverse(routeList.Items)
					}
					routeOrders = append(routeOrders, []string{routeList.Items[0].Name, routeList.Items[1].Name})
				case *gatewayv1.GRPCRouteList:
					if tt.kind != "GRPCRoute" {
						return nil
					}
					require.Len(t, routeList.Items, 2)
					slices.SortFunc(routeList.Items, func(a, b gatewayv1.GRPCRoute) int {
						return a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time)
					})
					if reverseRouteOrder {
						slices.Reverse(routeList.Items)
					}
					routeOrders = append(routeOrders, []string{routeList.Items[0].Name, routeList.Items[1].Name})
				}
				return nil
			}
			funcs.Patch = func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				if _, ok := obj.(*ciliumv2.CiliumEnvoyConfig); ok {
					cecPatches++
				}
				return c.Patch(ctx, obj, patch, opts...)
			}
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				WithStatusSubresource(&corev1.Service{}, &gatewayv1.HTTPRoute{}, &gatewayv1.GRPCRoute{}).
				WithIndex(&gatewayv1.HTTPRoute{}, indexers.GammaHTTPRouteParentRefsIndex, indexers.IndexHTTPRouteByGammaService).
				WithIndex(&gatewayv1.GRPCRoute{}, indexers.GammaGRPCRouteParentRefsIndex, indexers.IndexGRPCRouteByGammaService).
				WithInterceptorFuncs(funcs).
				Build()
			config := translation.Config{}
			r := &gammaReconciler{
				client:         c,
				translator:     gatewayApiTranslation.NewTranslator(translation.NewCECTranslator(config), config),
				logger:         logger,
				controllerName: defaultControllerName,
			}
			req := ctrl.Request{NamespacedName: serviceKeyEcho}
			result, err := r.Reconcile(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)

			for _, route := range routes {
				require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(route), route))
				var parents []gatewayv1.RouteParentStatus
				switch route := route.(type) {
				case *gatewayv1.HTTPRoute:
					parents = route.Status.Parents
				case *gatewayv1.GRPCRoute:
					parents = route.Status.Parents
				}
				require.Len(t, parents, 1)
				require.True(t, meta.IsStatusConditionTrue(parents[0].Conditions, string(gatewayv1.RouteConditionAccepted)))
				require.True(t, meta.IsStatusConditionTrue(parents[0].Conditions, string(gatewayv1.RouteConditionResolvedRefs)))
			}
			before := &ciliumv2.CiliumEnvoyConfig{}
			require.NoError(t, c.Get(t.Context(), serviceKeyEcho, before))
			require.NotEmpty(t, before.Spec.Resources)
			require.Len(t, before.OwnerReferences, 1)
			cecPatches = 0
			reverseRouteOrder = true

			result, err = r.Reconcile(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)
			after := &ciliumv2.CiliumEnvoyConfig{}
			require.NoError(t, c.Get(t.Context(), serviceKeyEcho, after))

			assert.Equal(t, [][]string{{"older", "newer"}, {"newer", "older"}}, routeOrders)
			assert.Empty(t, cmp.Diff(before.Spec, after.Spec, protocmp.Transform()))
			assert.Equal(t, before.OwnerReferences, after.OwnerReferences)
			assert.Zero(t, cecPatches, "Reordering routes must not patch CiliumEnvoyConfig")
			assert.Equal(t, before.ResourceVersion, after.ResourceVersion)
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
