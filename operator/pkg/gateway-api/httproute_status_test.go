// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func Test_httpRouteAcceptedCondition(t *testing.T) {
	type args struct {
		hr       *gatewayv1beta1.HTTPRoute
		accepted bool
		msg      string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "accepted http route",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				accepted: true,
				msg:      "Accepted HTTPRoute",
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "True",
				ObservedGeneration: 100,
				Reason:             "Accepted",
				Message:            "Accepted HTTPRoute",
			},
		},
		{
			name: "non-accepted http route",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				accepted: false,
				msg:      "Invalid HTTPRoute",
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "InvalidHTTPRoute",
				Message:            "Invalid HTTPRoute",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpRouteAcceptedCondition(tt.args.hr, tt.args.accepted, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "httpRouteAcceptedCondition() = %v, want %v", got, tt.want)
		})
	}
}

func Test_httpBackendNotFoundRouteCondition(t *testing.T) {
	type args struct {
		hr  *gatewayv1beta1.HTTPRoute
		msg string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "http backend not found",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				msg: "Backend not found",
			},
			want: metav1.Condition{
				Type:               "ResolvedRefs",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "BackendNotFound",
				Message:            "Backend not found",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpBackendNotFoundRouteCondition(tt.args.hr, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "httpBackendNotFoundRouteCondition(%v, %v)", tt.args.hr, tt.args.msg)
		})
	}
}

func Test_httpNoMatchingListenerHostnameRouteCondition(t *testing.T) {
	type args struct {
		hr  *gatewayv1beta1.HTTPRoute
		msg string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "no matching listener hostname",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				msg: "No matching listener",
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "NoMatchingListenerHostname",
				Message:            "No matching listener",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpNoMatchingListenerHostnameRouteCondition(tt.args.hr, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "httpNoMatchingListenerHostnameRouteCondition(%v, %v)", tt.args.hr, tt.args.msg)
		})
	}
}

func Test_httpRefNotPermittedRouteCondition(t *testing.T) {
	type args struct {
		hr  *gatewayv1beta1.HTTPRoute
		msg string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "ref not permitted",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				msg: "Reference not permitted",
			},
			want: metav1.Condition{
				Type:               "ResolvedRefs",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "RefNotPermitted",
				Message:            "Reference not permitted",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpRefNotPermittedRouteCondition(tt.args.hr, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "httpRefNotPermittedRouteCondition(%v, %v)", tt.args.hr, tt.args.msg)
		})
	}
}

func Test_httpInvalidKindRouteCondition(t *testing.T) {
	type args struct {
		hr  *gatewayv1beta1.HTTPRoute
		msg string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "invalid kind route",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				msg: "Invalid kind",
			},
			want: metav1.Condition{
				Type:               "ResolvedRefs",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "InvalidKind",
				Message:            "Invalid kind",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpInvalidKindRouteCondition(tt.args.hr, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "httpNoMatchingListenerHostnameRouteCondition(%v, %v)", tt.args.hr, tt.args.msg)
		})
	}
}

func Test_mergeHTTPRouteStatusConditions(t *testing.T) {
	type args struct {
		hr        *gatewayv1beta1.HTTPRoute
		parentRef gatewayv1beta1.ParentReference
		updates   []metav1.Condition
	}
	tests := []struct {
		name     string
		args     args
		expected gatewayv1beta1.HTTPRouteStatus
	}{
		{
			name: "create new http route status",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					Status: gatewayv1beta1.HTTPRouteStatus{},
				},
				parentRef: gatewayv1beta1.ParentReference{
					Name: "test-gateway",
				},
				updates: []metav1.Condition{
					{
						Type:               "Accepted",
						Status:             "True",
						ObservedGeneration: 100,
						Reason:             "Accepted",
						Message:            "Valid HTTPRoute",
					},
				},
			},
			expected: gatewayv1beta1.HTTPRouteStatus{
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
		{
			name: "Update the existing http route status with new condition",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
					Status: gatewayv1beta1.HTTPRouteStatus{},
				},
				parentRef: gatewayv1beta1.ParentReference{
					Name: "test-gateway",
				},
				updates: []metav1.Condition{
					{
						Type:               "ResolvedRefs",
						Status:             "False",
						ObservedGeneration: 100,
						Reason:             "InvalidKind",
						Message:            "Invalid kind",
					},
				},
			},
			expected: gatewayv1beta1.HTTPRouteStatus{
				RouteStatus: gatewayv1beta1.RouteStatus{
					Parents: []gatewayv1beta1.RouteParentStatus{
						{
							ParentRef: gatewayv1beta1.ParentReference{
								Name: "test-gateway",
							},
							ControllerName: "io.cilium/gateway-controller",
							Conditions: []metav1.Condition{
								{
									Type:               "ResolvedRefs",
									Status:             "False",
									ObservedGeneration: 100,
									Reason:             "InvalidKind",
									Message:            "Invalid kind",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Update the existing http route status with existing condition",
			args: args{
				hr: &gatewayv1beta1.HTTPRoute{
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
											Status:             "False",
											ObservedGeneration: 100,
											Reason:             "Accepted",
											Message:            "Invalid HTTPRoute",
										},
									},
								},
							},
						},
					},
				},
				parentRef: gatewayv1beta1.ParentReference{
					Name: "test-gateway",
				},
				updates: []metav1.Condition{
					{
						Type:               "Accepted",
						Status:             "True",
						ObservedGeneration: 100,
						Reason:             "Accepted",
						Message:            "Valid HTTPRoute",
					},
				},
			},
			expected: gatewayv1beta1.HTTPRouteStatus{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mergeHTTPRouteStatusConditions(tt.args.hr, tt.args.parentRef, tt.args.updates)
			require.True(t, cmp.Equal(tt.args.hr.Status, tt.expected, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")))
		})
	}
}
