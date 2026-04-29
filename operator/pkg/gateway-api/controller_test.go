// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
)

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
					ObjectOld: &gatewayv1.TLSRoute{},
					ObjectNew: &gatewayv1.TLSRoute{},
				},
			},
			expected: false,
		},
		{
			name: "change in TLSRoute status",
			args: args{
				evt: event.UpdateEvent{
					ObjectOld: &gatewayv1.TLSRoute{},
					ObjectNew: &gatewayv1.TLSRoute{
						Status: gatewayv1.TLSRouteStatus{
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
					ObjectOld: &gatewayv1.TLSRoute{
						Status: gatewayv1.TLSRouteStatus{
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
					ObjectNew: &gatewayv1.TLSRoute{
						Status: gatewayv1.TLSRouteStatus{
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
