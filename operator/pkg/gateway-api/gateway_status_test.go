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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestValidateTLSFrontend(t *testing.T) {
	tests := []struct {
		name                      string
		seedInsecureCondition     bool
		defaultMode               gatewayv1.FrontendValidationModeType
		hasPerPortValidation      bool
		perPortMode               gatewayv1.FrontendValidationModeType
		wantInsecureModeCondition bool
	}{
		{
			name:                      "default fallback sets the condition",
			defaultMode:               gatewayv1.AllowInsecureFallback,
			wantInsecureModeCondition: true,
		},
		{
			name:                      "per-port fallback keeps the condition",
			seedInsecureCondition:     true,
			defaultMode:               gatewayv1.AllowValidOnly,
			hasPerPortValidation:      true,
			perPortMode:               gatewayv1.AllowInsecureFallback,
			wantInsecureModeCondition: true,
		},
		{
			name:                  "valid-only modes remove the condition",
			seedInsecureCondition: true,
			defaultMode:           gatewayv1.AllowValidOnly,
			hasPerPortValidation:  true,
			perPortMode:           gatewayv1.AllowValidOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &GatewayStatusManager{}
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Generation: 7},
				Spec: gatewayv1.GatewaySpec{
					TLS: &gatewayv1.GatewayTLSConfig{
						Frontend: &gatewayv1.FrontendTLSConfig{
							Default: gatewayv1.TLSConfig{
								Validation: &gatewayv1.FrontendTLSValidation{Mode: gatewayv1.AllowInsecureFallback},
							},
						},
					},
				},
			}

			conditionType := string(gatewayv1.GatewayConditionInsecureFrontendValidationMode)
			if tt.seedInsecureCondition {
				manager.validateTLSFrontend(gw)
				require.NotNil(t, findListenerCondition(gw.Status.Conditions, conditionType), "expected insecure condition before applying the test configuration")
			}

			gw.Spec.TLS.Frontend.Default.Validation.Mode = tt.defaultMode
			if tt.hasPerPortValidation {
				gw.Spec.TLS.Frontend.PerPort = []gatewayv1.TLSPortConfig{{
					Port: 8443,
					TLS: gatewayv1.TLSConfig{
						Validation: &gatewayv1.FrontendTLSValidation{Mode: tt.perPortMode},
					},
				}}
			}

			manager.validateTLSFrontend(gw)
			condition := findListenerCondition(gw.Status.Conditions, conditionType)
			if !tt.wantInsecureModeCondition {
				assert.Nil(t, condition)
				return
			}

			require.NotNil(t, condition)
			assert.Equal(t, metav1.ConditionTrue, condition.Status)
			assert.Equal(t, string(gatewayv1.GatewayReasonConfigurationChanged), condition.Reason)
			assert.Equal(t, gw.Generation, condition.ObservedGeneration)
		})
	}
}

func Test_gatewayStatusScheduledCondition(t *testing.T) {
	type args struct {
		gw        *gatewayv1.Gateway
		scheduled bool
		msg       string
		reason    gatewayv1.GatewayConditionReason
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "scheduled",
			args: args{
				gw: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				reason:    gatewayv1.GatewayReasonAccepted,
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
				gw: &gatewayv1.Gateway{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 100,
					},
				},
				scheduled: false,
				reason:    gatewayv1.GatewayReasonNoResources,
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
			got := gatewayStatusAcceptedCondition(tt.args.gw, tt.args.scheduled, tt.args.msg, tt.args.reason)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "gatewayStatusAcceptedCondition() = %v, want %v", got, tt.want)
		})
	}
}

func Test_listenerProgrammedCondition(t *testing.T) {
	type args struct {
		generation int64
		ready      bool
		reason     gatewayv1.ListenerConditionReason
		msg        string
	}
	tests := []struct {
		name string
		args args
		want metav1.Condition
	}{
		{
			name: "ready",
			args: args{
				generation: 100,
				ready:      true,
				reason:     gatewayv1.ListenerConditionReason(gatewayv1.ListenerConditionProgrammed),
				msg:        "Listener Ready",
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
				generation: 100,
				ready:      false,
				reason:     gatewayv1.ListenerReasonPending,
				msg:        "Listener Pending",
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
			got := listenerProgrammedCondition(tt.args.generation, tt.args.ready, tt.args.reason, tt.args.msg)
			assert.True(t, cmp.Equal(got, tt.want, cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")), "listenerProgrammedCondition() = %v, want %v", got, tt.want)
		})
	}
}
