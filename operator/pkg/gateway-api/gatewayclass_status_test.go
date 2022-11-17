// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func Test_gatewayClassAcceptedCondition(t *testing.T) {
	type args struct {
		gwc      *gatewayv1beta1.GatewayClass
		accepted bool
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "accepted gateway class",
			args: args{
				gwc: &gatewayv1beta1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				accepted: true,
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "True",
				ObservedGeneration: 100,
				Reason:             "Accepted",
				Message:            "Valid GatewayClass",
			},
		},
		{
			name: "non-accepted gateway class",
			args: args{
				gwc: &gatewayv1beta1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				accepted: false,
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "InvalidParameters",
				Message:            "Invalid GatewayClass",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatewayClassAcceptedCondition(tt.args.gwc, tt.args.accepted)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "httpRouteAcceptedCondition() = %v, want %v", got, tt.want)
		})
	}
}
