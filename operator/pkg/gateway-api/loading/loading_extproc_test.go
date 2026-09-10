// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loading

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// TestLoadLoadsExtProcBackendServices ensures the Services backing ext_proc
// filters are loaded. They are named by the CiliumEnvoyExtProcFilter rather than
// by a Route backend reference, so nothing else in the reference set reaches
// them and every ext_proc route would otherwise fail closed.
func TestLoadLoadsExtProcBackendServices(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "cilium"},
	}

	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
	}

	extensionRef := func(name string) gatewayv1.HTTPRouteFilter {
		return gatewayv1.HTTPRouteFilter{
			Type: gatewayv1.HTTPRouteFilterExtensionRef,
			ExtensionRef: &gatewayv1.LocalObjectReference{
				Group: "cilium.io",
				Kind:  "CiliumEnvoyExtProcFilter",
				Name:  gatewayv1.ObjectName(name),
			},
		}
	}

	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "route-backend",
									Port: ptr.To[gatewayv1.PortNumber](80),
								},
							},
						},
					},
					Filters: []gatewayv1.HTTPRouteFilter{extensionRef("local-filter")},
				},
				{
					Filters: []gatewayv1.HTTPRouteFilter{extensionRef("cross-filter")},
				},
			},
		},
	}

	// localFilter omits backendRef.namespace, so it must resolve against the
	// filter's own namespace and not the Route's.
	localFilter := &ciliumv2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "local-filter", Namespace: "filters"},
		Spec: ciliumv2alpha1.CiliumEnvoyExtProcFilterSpec{
			BackendRef: ciliumv2alpha1.ExtProcBackendRef{Name: "ext-proc-backend", Port: 4317},
		},
	}

	crossFilter := &ciliumv2alpha1.CiliumEnvoyExtProcFilter{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-filter", Namespace: "filters"},
		Spec: ciliumv2alpha1.CiliumEnvoyExtProcFilterSpec{
			BackendRef: ciliumv2alpha1.ExtProcBackendRef{
				Name:      "remote-backend",
				Namespace: ptr.To("other"),
				Port:      4317,
			},
		},
	}

	svc := func(namespace, name string) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	}

	// decoyBackend shares its name with the filter's backend but sits in the
	// Route's namespace. Defaulting to the Route's namespace would load it.
	decoyBackend := svc("default", "ext-proc-backend")

	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(
			gw,
			gwc,
			httpRoute,
			localFilter,
			crossFilter,
			svc("default", "route-backend"),
			svc("filters", "ext-proc-backend"),
			svc("other", "remote-backend"),
			svc("default", "unrelated"),
			decoyBackend,
		).
		WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway).
		WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway).
		WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway).
		Build()

	t.Run("filter backends are loaded and namespace defaults to the filter", func(t *testing.T) {
		loader := NewTranslationInputLoader(c, logger, "io.cilium/gateway-controller", TranslationInputLoaderConfig{
			IncludeExtProcFilters: true,
		})

		inputs, err := loader.Load(t.Context(), logger, gw, gwc)
		require.NoError(t, err)

		require.Equal(t, []client.ObjectKey{
			{Namespace: "default", Name: "route-backend"},
			{Namespace: "filters", Name: "ext-proc-backend"},
			{Namespace: "other", Name: "remote-backend"},
		}, serviceKeys(inputs.Services))
		require.Len(t, inputs.ExtProcFilters, 2)
	})

	t.Run("nothing is loaded while ext_proc ExtensionRefs are disabled", func(t *testing.T) {
		loader := NewTranslationInputLoader(c, logger, "io.cilium/gateway-controller", TranslationInputLoaderConfig{})

		inputs, err := loader.Load(t.Context(), logger, gw, gwc)
		require.NoError(t, err)

		require.Equal(t, []client.ObjectKey{
			{Namespace: "default", Name: "route-backend"},
		}, serviceKeys(inputs.Services))
		require.Empty(t, inputs.ExtProcFilters)
	})
}
