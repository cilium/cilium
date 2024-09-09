// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func testScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))

	registerGatewayAPITypesToScheme(scheme, optionalGVKs)

	return scheme
}

var controllerTestFixture = []client.Object{
	// Cilium Gateway Class
	&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium",
		},
		Spec: gatewayv1.GatewayClassSpec{
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
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Hostname: ptr.To[gatewayv1.Hostname]("example.com"),
					Port:     443,
					TLS: &gatewayv1.GatewayTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Name: "tls-secret",
							},
						},
					},
				},
			},
		},
	},

	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway-2",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "https",
					Hostname: ptr.To[gatewayv1.Hostname]("example2.com"),
					Port:     443,
					TLS: &gatewayv1.GatewayTLSConfig{
						CertificateRefs: []gatewayv1.SecretObjectReference{},
					},
				},
			},
		},
	},

	// Gateway with no TLS listener
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-no-tls",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
				},
			},
		},
	},

	// Gateway for TLSRoute
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-tlsroute",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tls",
					Protocol: gatewayv1.TLSProtocolType,
					Port:     443,
				},
			},
		},
	},

	// Gateway with allowed route in same namespace only
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-from-same-namespace",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSame),
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes from ALL namespace
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-from-all-namespaces",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromAll),
						},
					},
				},
			},
		},
	},

	// Gateway with allowed routes with selector
	&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway-with-namespaces-selector",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				{
					Name: "https",
					Port: 80,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Namespaces: &gatewayv1.RouteNamespaces{
							From: ptr.To(gatewayv1.NamespacesFromSelector),
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
	logger := hivetest.Logger(t)
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(controllerTestFixture...).Build()
	fn := hasMatchingController(context.Background(), c, "io.cilium/gateway-controller", logger)

	t.Run("invalid object", func(t *testing.T) {
		res := fn(&corev1.Pod{})
		require.False(t, res)
	})

	t.Run("gateway is matched by controller", func(t *testing.T) {
		res := fn(&gatewayv1.Gateway{
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "cilium",
			},
		})
		require.True(t, res)
	})

	t.Run("gateway is linked to non-existent class", func(t *testing.T) {
		res := fn(&gatewayv1.Gateway{
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: "non-existent",
			},
		})
		require.False(t, res)
	})
}

func Test_getGatewaysForSecret(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(controllerTestFixture...).Build()
	logger := hivetest.Logger(t)

	t.Run("secret is used in gateway", func(t *testing.T) {
		gwList := getGatewaysForSecret(context.Background(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
		}, logger)

		require.Len(t, gwList, 1)
		require.Equal(t, "valid-gateway", gwList[0].Name)
	})

	t.Run("secret is not used in gateway", func(t *testing.T) {
		gwList := getGatewaysForSecret(context.Background(), c, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret-not-used",
				Namespace: "default",
			},
		}, logger)

		require.Len(t, gwList, 0)
	})
}

func Test_getGatewaysForNamespace(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(namespaceFixtures...).
		WithObjects(controllerTestFixture...).
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
			gwList := getGatewaysForNamespace(context.Background(), c, &corev1.Namespace{
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

func Test_success(t *testing.T) {
	tests := []struct {
		name    string
		want    ctrl.Result
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "success",
			want:    ctrl.Result{},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := controllerruntime.Success()
			if !tt.wantErr(t, err, "success()") {
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
		want    ctrl.Result
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "fail",
			args: args{
				e: errors.New("fail"),
			},
			want:    ctrl.Result{},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := controllerruntime.Fail(tt.args.e)
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
					ObjectOld: &gatewayv1.GatewayClass{},
					ObjectNew: &gatewayv1.Gateway{},
				},
			},
			expected: false,
		},
		{
			name: "mismatch kind for Gateway",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.Gateway{},
					ObjectNew: &gatewayv1.GatewayClass{},
				},
			},
			expected: false,
		},
		{
			name: "mismatch kind for HTTPRoute",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.HTTPRoute{},
					ObjectNew: &gatewayv1.GatewayClass{},
				},
			},
			expected: false,
		},
		{
			name: "no change in GatewayClass status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.GatewayClass{},
					ObjectNew: &gatewayv1.GatewayClass{},
				},
			},
			expected: false,
		},
		{
			name: "change in GatewayClass status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.GatewayClass{},
					ObjectNew: &gatewayv1.GatewayClass{
						Status: gatewayv1.GatewayClassStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1.GatewayConditionAccepted),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1.GatewayReasonAccepted),
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
					ObjectOld: &gatewayv1.Gateway{
						Status: gatewayv1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1.GatewayConditionAccepted),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1.GatewayReasonAccepted),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
					ObjectNew: &gatewayv1.Gateway{
						Status: gatewayv1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1.GatewayConditionAccepted),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1.GatewayReasonAccepted),
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
					ObjectOld: &gatewayv1.Gateway{},
					ObjectNew: &gatewayv1.Gateway{},
				},
			},
			expected: false,
		},
		{
			name: "change in gateway status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.Gateway{},
					ObjectNew: &gatewayv1.Gateway{
						Status: gatewayv1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1.GatewayConditionAccepted),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1.GatewayReasonAccepted),
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
					ObjectOld: &gatewayv1.Gateway{
						Status: gatewayv1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1.GatewayConditionAccepted),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1.GatewayReasonAccepted),
									LastTransitionTime: metav1.NewTime(time.Now()),
								},
							},
						},
					},
					ObjectNew: &gatewayv1.Gateway{
						Status: gatewayv1.GatewayStatus{
							Conditions: []metav1.Condition{
								{
									Type:               string(gatewayv1.GatewayConditionAccepted),
									Status:             metav1.ConditionTrue,
									Reason:             string(gatewayv1.GatewayReasonAccepted),
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
					ObjectOld: &gatewayv1.HTTPRoute{},
					ObjectNew: &gatewayv1.HTTPRoute{},
				},
			},
			expected: false,
		},
		{
			name: "change in HTTP route status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.HTTPRoute{},
					ObjectNew: &gatewayv1.HTTPRoute{
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
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
					ObjectOld: &gatewayv1.HTTPRoute{
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
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
					ObjectNew: &gatewayv1.HTTPRoute{
						Status: gatewayv1.HTTPRouteStatus{
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
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
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
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
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
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
							RouteStatus: gatewayv1.RouteStatus{
								Parents: []gatewayv1.RouteParentStatus{
									{
										ParentRef: gatewayv1.ParentReference{
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
