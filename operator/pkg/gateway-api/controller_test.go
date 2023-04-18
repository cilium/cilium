// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/model"
)

var controllerTestFixture = []client.Object{
	// Cilium Gateway Class
	&gatewayv1beta1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1beta1.GatewayClassSpec{
			ControllerName: "io.cilium/gateway-controller",
		},
	},

	// Secret used in Gateway
	&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-secret",
			Namespace: "default",
		},
		StringData: map[string]string{
			"tls.crt": "cert",
			"tls.key": "key",
		},
		Type: corev1.SecretTypeTLS,
	},

	// Gateway with valid TLS secret
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "https",
					Hostname: model.AddressOf[gatewayv1beta1.Hostname]("example.com"),
					Port:     443,
					TLS: &gatewayv1beta1.GatewayTLSConfig{
						CertificateRefs: []gatewayv1beta1.SecretObjectReference{
							{
								Name: "tls-secret",
							},
						},
					},
				},
			},
		},
	},

	// Gateway with no TLS listener
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-no-tls",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name: "https",
					Port: 80,
				},
			},
		},
	},

	// Gateway for TLSRoute
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-tlsroute",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name:     "tls",
					Protocol: gatewayv1beta1.TLSProtocolType,
					Port:     443,
				},
			},
		},
	},

	// Gateway with allowed route in same namespace only
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-from-same-namespace",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
						Namespaces: &gatewayv1beta1.RouteNamespaces{
							From: model.AddressOf(gatewayv1beta1.NamespacesFromSame),
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes from ALL namespace
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-from-all-namespaces",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
						Namespaces: &gatewayv1beta1.RouteNamespaces{
							From: model.AddressOf(gatewayv1beta1.NamespacesFromAll),
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes with selector
	&gatewayv1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-namespaces-selector",
			Namespace: "default",
		},
		Spec: gatewayv1beta1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1beta1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1beta1.AllowedRoutes{
						Namespaces: &gatewayv1beta1.RouteNamespaces{
							From: model.AddressOf(gatewayv1beta1.NamespacesFromSelector),
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"gateway": "allowed",
								},
							},
						},
					},
				},
			},
		},
	},
}

var namespaceFixtures = []client.Object{
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "another-namespace",
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-with-allowed-gateway-selector",
			Labels: map[string]string{
				"gateway": "allowed",
			},
		},
	},
	&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace-with-disallowed-gateway-selector",
			Labels: map[string]string{
				"gateway": "disallowed",
			},
		},
	},
}

func Test_hasMatchingController(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(controllerTestFixture...).Build()
	fn := hasMatchingController(context.Background(), c, "io.cilium/gateway-controller")

	t.Run("invalid object", func(t *testing.T) {
		res := fn(&corev1.Pod{})
		require.False(t, res)
	})

	t.Run("gateway is matched by controller", func(t *testing.T) {
		res := fn(&gatewayv1beta1.Gateway{
			Spec: gatewayv1beta1.GatewaySpec{
				GatewayClassName: "cilium",
			},
		})
		require.True(t, res)
	})

	t.Run("gateway is linked to non-existent class", func(t *testing.T) {
		res := fn(&gatewayv1beta1.Gateway{
			Spec: gatewayv1beta1.GatewaySpec{
				GatewayClassName: "non-existent",
			},
		})
		require.False(t, res)
	})
}

func Test_getGatewaysForSecret(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(controllerTestFixture...).Build()

	t.Run("secret is used in gateway", func(t *testing.T) {
		gwList := getGatewaysForSecret(context.Background(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
		})

		require.Len(t, gwList, 1)
		require.Equal(t, "valid-gateway", gwList[0].Name)
	})

	t.Run("secret is not used in gateway", func(t *testing.T) {
		gwList := getGatewaysForSecret(context.Background(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret-not-used",
				Namespace: "default",
			},
		})

		require.Len(t, gwList, 0)
	})
}

func Test_getGatewaysForNamespace(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespaceFixtures...).
		WithObjects(controllerTestFixture...).
		Build()

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
			gwList := getGatewaysForNamespace(context.Background(), c, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.args.namespace,
				},
			})
			names := make([]string, 0, len(gwList))
			for _, gw := range gwList {
				names = append(names, gw.Name)
			}
			require.ElementsMatch(t, tt.want, names)
		})
	}
}

func Test_success(t *testing.T) {
	tests := []struct {
		name    string
		want    controllerruntime.Result
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "success",
			want:    controllerruntime.Result{},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := success()
			if !tt.wantErr(t, err, fmt.Sprintf("success()")) {
				return
			}
			assert.Equalf(t, tt.want, got, "success()")
		})
	}
}

func Test_fail(t *testing.T) {
	type args struct {
		e error
	}
	tests := []struct {
		name    string
		args    args
		want    controllerruntime.Result
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "fail",
			args: args{
				e: errors.New("fail"),
			},
			want:    controllerruntime.Result{},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fail(tt.args.e)
			if !tt.wantErr(t, err, fmt.Sprintf("fail(%v)", tt.args.e)) {
				return
			}
			assert.Equalf(t, tt.want, got, "fail(%v)", tt.args.e)
		})
	}
}

func Test_onlyStatusChanged(t *testing.T) {
	failingFuncs := predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool {
			t.Fail()
			return false
		},
		DeleteFunc: func(event.DeleteEvent) bool {
			t.Fail()
			return false
		},
		UpdateFunc: func(event.UpdateEvent) bool {
			t.Fail()
			return false
		},
		GenericFunc: func(event.GenericEvent) bool {
			t.Fail()
			return false
		},
	}
	f := failingFuncs
	f.UpdateFunc = onlyStatusChanged().Update

	type args struct {
		evt event.UpdateEvent
	}
	tests := []struct {
		name     string
		args     args
		expected bool
	}{
		{
			name: "unsupported kind",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &corev1.Pod{},
					ObjectNew: &corev1.Pod{},
				},
			},
			expected: false,
		},
		{
			name: "mismatch kind for GatewayClass",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.GatewayClass{},
					ObjectNew: &gatewayv1beta1.Gateway{},
				},
			},
			expected: false,
		},
		{
			name: "mismatch kind for Gateway",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.Gateway{},
					ObjectNew: &gatewayv1beta1.GatewayClass{},
				},
			},
			expected: false,
		},
		{
			name: "mismatch kind for HTTPRoute",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.HTTPRoute{},
					ObjectNew: &gatewayv1beta1.GatewayClass{},
				},
			},
			expected: false,
		},
		{
			name: "no change in GatewayClass status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.GatewayClass{},
					ObjectNew: &gatewayv1beta1.GatewayClass{},
				},
			},
			expected: false,
		},
		{
			name: "change in GatewayClass status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.GatewayClass{},
					ObjectNew: &gatewayv1beta1.GatewayClass{
						Status: gatewayv1beta1.GatewayClassStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1beta1.GatewayConditionScheduled),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "only change LastTransitionTime in GatewayClass status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.Gateway{
						Status: gatewayv1beta1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1beta1.GatewayConditionScheduled),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
					ObjectNew: &gatewayv1beta1.Gateway{
						Status: gatewayv1beta1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1beta1.GatewayConditionScheduled),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},

		{
			name: "no change in gateway status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.Gateway{},
					ObjectNew: &gatewayv1beta1.Gateway{},
				},
			},
			expected: false,
		},
		{
			name: "change in gateway status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.Gateway{},
					ObjectNew: &gatewayv1beta1.Gateway{
						Status: gatewayv1beta1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1beta1.GatewayConditionScheduled),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "only change LastTransitionTime in gateway status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.Gateway{
						Status: gatewayv1beta1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1beta1.GatewayConditionScheduled),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
					ObjectNew: &gatewayv1beta1.Gateway{
						Status: gatewayv1beta1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1beta1.GatewayConditionScheduled),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1beta1.GatewayReasonScheduled),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "no change in HTTPRoute status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.HTTPRoute{},
					ObjectNew: &gatewayv1beta1.HTTPRoute{},
				},
			},
			expected: false,
		},
		{
			name: "change in HTTP route status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.HTTPRoute{},
					ObjectNew: &gatewayv1beta1.HTTPRoute{
						Status: gatewayv1beta1.HTTPRouteStatus{
							RouteStatus: gatewayv1beta1.RouteStatus{
								Parents: []gatewayv1beta1.RouteParentStatus{
									{
										ParentRef: gatewayv1beta1.ParentReference{
											Name: "test-gateway",
										},
										ControllerName: "io.cilium/gateway-controller",
										Conditions: []metav1.Condition{
											{
												Type:               "Accepted",
												Status:             "True",
												ObservedGeneration: 100,
												Reason:             "Accepted",
												Message:            "Valid HTTPRoute",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "only change LastTransitionTime in HTTPRoute status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1beta1.HTTPRoute{
						Status: gatewayv1beta1.HTTPRouteStatus{
							RouteStatus: gatewayv1beta1.RouteStatus{
								Parents: []gatewayv1beta1.RouteParentStatus{
									{
										ParentRef: gatewayv1beta1.ParentReference{
											Name: "test-gateway",
										},
										ControllerName: "io.cilium/gateway-controller",
										Conditions: []metav1.Condition{
											{
												Type:               "Accepted",
												Status:             "True",
												ObservedGeneration: 100,
												Reason:             "Accepted",
												Message:            "Valid HTTPRoute",
											},
										},
									},
								},
							},
						},
					},
					ObjectNew: &gatewayv1beta1.HTTPRoute{
						Status: gatewayv1beta1.HTTPRouteStatus{
							RouteStatus: gatewayv1beta1.RouteStatus{
								Parents: []gatewayv1beta1.RouteParentStatus{
									{
										ParentRef: gatewayv1beta1.ParentReference{
											Name: "test-gateway",
										},
										ControllerName: "io.cilium/gateway-controller",
										Conditions: []metav1.Condition{
											{
												Type:               "Accepted",
												Status:             "True",
												ObservedGeneration: 100,
												Reason:             "Accepted",
												Message:            "Valid HTTPRoute",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "no change in TLSRoute status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1alpha2.TLSRoute{},
					ObjectNew: &gatewayv1alpha2.TLSRoute{},
				},
			},
			expected: false,
		},
		{
			name: "change in TLSRoute status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1alpha2.TLSRoute{},
					ObjectNew: &gatewayv1alpha2.TLSRoute{
						Status: gatewayv1alpha2.TLSRouteStatus{
							RouteStatus: gatewayv1beta1.RouteStatus{
								Parents: []gatewayv1beta1.RouteParentStatus{
									{
										ParentRef: gatewayv1beta1.ParentReference{
											Name: "test-gateway",
										},
										ControllerName: "io.cilium/gateway-controller",
										Conditions: []metav1.Condition{
											{
												Type:               "Accepted",
												Status:             "True",
												ObservedGeneration: 100,
												Reason:             "Accepted",
												Message:            "Valid TLSRoute",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "only change LastTransitionTime in TLSRoute status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1alpha2.TLSRoute{
						Status: gatewayv1alpha2.TLSRouteStatus{
							RouteStatus: gatewayv1beta1.RouteStatus{
								Parents: []gatewayv1beta1.RouteParentStatus{
									{
										ParentRef: gatewayv1beta1.ParentReference{
											Name: "test-gateway",
										},
										ControllerName: "io.cilium/gateway-controller",
										Conditions: []metav1.Condition{
											{
												Type:               "Accepted",
												Status:             "True",
												ObservedGeneration: 100,
												Reason:             "Accepted",
												Message:            "Valid TLSRoute",
											},
										},
									},
								},
							},
						},
					},
					ObjectNew: &gatewayv1alpha2.TLSRoute{
						Status: gatewayv1alpha2.TLSRouteStatus{
							RouteStatus: gatewayv1beta1.RouteStatus{
								Parents: []gatewayv1beta1.RouteParentStatus{
									{
										ParentRef: gatewayv1beta1.ParentReference{
											Name: "test-gateway",
										},
										ControllerName: "io.cilium/gateway-controller",
										Conditions: []metav1.Condition{
											{
												Type:               "Accepted",
												Status:             "True",
												ObservedGeneration: 100,
												Reason:             "Accepted",
												Message:            "Valid TLSRoute",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := f.Update(tt.args.evt)
			assert.Equal(t, tt.expected, res)
		})
	}
}
