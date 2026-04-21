// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers/testhelpers"
)

func Test_getGatewaysForNamespace(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
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
			gwList := getGatewaysForNamespace(t.Context(), c, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.args.namespace,
				},
			}, logger)
			names := make([]string, 0, len(gwList))
			for _, gw := range gwList {
				names = append(names, gw.Name)
			}
			require.ElementsMatch(t, tt.want, names)
		})
	}
}
