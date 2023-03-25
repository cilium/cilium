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

func Test_gatewayStatusScheduledCondition(t *testing.T) {
	type args struct {
		gw        *gatewayv1beta1.Gateway
		scheduled bool
		msg       string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "scheduled",
			args: args{
				gw: &gatewayv1beta1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				scheduled: true,
				msg:       "Scheduled Gateway",
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "True",
				ObservedGeneration: 100,
				Reason:             "Accepted",
				Message:            "Scheduled Gateway",
			},
		},
		{
			name: "non-scheduled",
			args: args{
				gw: &gatewayv1beta1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				scheduled: false,
				msg:       "Invalid Gateway",
			},
			want: metav1.Condition{
				Type:               "Accepted",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "NoResources",
				Message:            "Invalid Gateway",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatewayStatusAcceptedCondition(tt.args.gw, tt.args.scheduled, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "gatewayStatusAcceptedCondition() = %v, want %v", got, tt.want)
		})
	}
}

func Test_gatewayStatusReadyCondition(t *testing.T) {
	type args struct {
		gw    *gatewayv1beta1.Gateway
		ready bool
		msg   string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "ready",
			args: args{
				gw: &gatewayv1beta1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				ready: true,
				msg:   "Listener Ready",
			},
			want: metav1.Condition{
				Type:               "Ready",
				Status:             "True",
				ObservedGeneration: 100,
				Reason:             "Ready",
				Message:            "Listener Ready",
			},
		},
		{
			name: "unready",
			args: args{
				gw: &gatewayv1beta1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				ready: false,
				msg:   "Listener Pending",
			},
			want: metav1.Condition{
				Type:               "Ready",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "ListenersNotReady",
				Message:            "Listener Pending",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatewayStatusReadyCondition(tt.args.gw, tt.args.ready, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "gatewayStatusAcceptedCondition() = %v, want %v", got, tt.want)
		})
	}
}

func Test_gatewayListenerProgrammedCondition(t *testing.T) {
	type args struct {
		gw    *gatewayv1beta1.Gateway
		ready bool
		msg   string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "ready",
			args: args{
				gw: &gatewayv1beta1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				ready: true,
				msg:   "Listener Ready",
			},
			want: metav1.Condition{
				Type:               "Programmed",
				Status:             "True",
				ObservedGeneration: 100,
				Reason:             "Programmed",
				Message:            "Listener Ready",
			},
		},
		{
			name: "unready",
			args: args{
				gw: &gatewayv1beta1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				ready: false,
				msg:   "Listener Pending",
			},
			want: metav1.Condition{
				Type:               "Programmed",
				Status:             "False",
				ObservedGeneration: 100,
				Reason:             "Pending",
				Message:            "Listener Pending",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatewayListenerProgrammedCondition(tt.args.gw, tt.args.ready, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "gatewayStatusAcceptedCondition() = %v, want %v", got, tt.want)
		})
	}
}
