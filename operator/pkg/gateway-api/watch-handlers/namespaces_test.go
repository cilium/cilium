// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
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
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func Test_getGatewaysForNamespace(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithObjects(testhelpers.NamespaceFixtures...).
		WithObjects(testhelpers.ControllerTestFixture...).
		Build()
	logger := hivetest.Logger(t)

	type args struct {
		namespace string
	}

	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "with default namespace",
			args: args{namespace: "default"},
			want: []string{"gateway-from-all-namespaces", "gateway-from-same-namespace"},
		},
		{
			name: "with another namespace",
			args: args{namespace: "another-namespace"},
			want: []string{"gateway-from-all-namespaces"},
		},
		{
			name: "with namespace-with-allowed-gateway-selector",
			args: args{namespace: "namespace-with-allowed-gateway-selector"},
			want: []string{"gateway-from-all-namespaces", "gateway-with-namespaces-selector"},
		},
		{
			name: "with namespace-with-disallowed-gateway-selector",
			args: args{namespace: "namespace-with-disallowed-gateway-selector"},
			want: []string{"gateway-from-all-namespaces"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwList := getGatewaysForNamespace(t.Context(), c, namespaceFixture(t, tt.args.namespace), logger)
			names := make([]string, 0, len(gwList))
			for _, gw := range gwList {
				names = append(names, gw.Name)
			}
			require.ElementsMatch(t, tt.want, names)
		})
	}
}

func Test_getGatewaysForNamespace_selector(t *testing.T) {
	selectorGateway := func(name string, expr metav1.LabelSelectorRequirement) *gatewayv1.Gateway {
		return &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "gateways"},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
				Listeners: []gatewayv1.Listener{{
					Name: "http",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{expr},
							},
						},
					},
				}},
			},
		}
	}
	namespace := func(name string, labels map[string]string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	}

	c := fake.NewClientBuilder().
		WithScheme(testhelpers.TestScheme(helpers.AllOptionalKinds, helpers.RegisterGatewayAPITypesToScheme)).
		WithObjects(
			namespace("gateways", nil),
			namespace("prod", map[string]string{"env": "prod"}),
			namespace("dev", map[string]string{"env": "dev"}),
			namespace("unlabelled", nil),
			selectorGateway("env-in-prod", metav1.LabelSelectorRequirement{
				Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"},
			}),
			selectorGateway("env-does-not-exist", metav1.LabelSelectorRequirement{
				Key: "env", Operator: metav1.LabelSelectorOpDoesNotExist,
			}),
		).
		Build()
	logger := hivetest.Logger(t)

	tests := []struct {
		name      string
		namespace client.Object
		want      []string
	}{
		{
			name:      "In expression matches",
			namespace: namespace("prod", map[string]string{"env": "prod"}),
			want:      []string{"env-in-prod"},
		},
		{
			name:      "no expression matches",
			namespace: namespace("dev", map[string]string{"env": "dev"}),
			want:      []string{},
		},
		{
			name:      "DoesNotExist expression matches",
			namespace: namespace("unlabelled", nil),
			want:      []string{"env-does-not-exist"},
		},
		{
			name:      "deleted namespace no longer in the cache",
			namespace: namespace("deleted", map[string]string{"env": "prod"}),
			want:      []string{"env-in-prod"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gwList := getGatewaysForNamespace(t.Context(), c, tt.namespace, logger)
			names := make([]string, 0, len(gwList))
			for _, gw := range gwList {
				names = append(names, gw.Name)
			}
			require.ElementsMatch(t, tt.want, names)
		})
	}
}

func namespaceFixture(t *testing.T, name string) *corev1.Namespace {
	t.Helper()
	for _, obj := range testhelpers.NamespaceFixtures {
		if ns, ok := obj.(*corev1.Namespace); ok && ns.Name == name {
			return ns
		}
	}
	t.Fatalf("no namespace fixture named %q", name)
	return nil
}
