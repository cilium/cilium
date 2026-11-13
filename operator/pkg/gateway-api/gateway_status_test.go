// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/hive/hivetest"
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

func TestGatewayStatusManager_validateStaticAddresses(t *testing.T) {
	namedAddressType := gatewayv1.NamedAddressType
	ipAddressType := gatewayv1.IPAddressType

	tests := []struct {
		name               string
		addresses          []gatewayv1.GatewaySpecAddress
		expectedValid      bool
		expectedAccepted   *metav1.Condition
		expectedProgrammed *metav1.Condition
	}{
		{
			name:          "no static addresses",
			addresses:     nil,
			expectedValid: true,
		},
		{
			name: "valid IPv4 address",
			addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddressType,
					Value: "192.0.2.1",
				},
			},
			expectedValid: true,
		},
		{
			name: "valid IPv6 address",
			addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddressType,
					Value: "2001:db8::1",
				},
			},
			expectedValid: true,
		},
		{
			name: "valid address with nil type defaults to IPAddress",
			addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  nil,
					Value: "192.0.2.2",
				},
			},
			expectedValid: true,
		},
		{
			name: "unsupported address type",
			addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &namedAddressType,
					Value: "my-named-address",
				},
			},
			expectedValid: false,
			expectedAccepted: &metav1.Condition{
				Type:    string(gatewayv1.GatewayConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.GatewayReasonUnsupportedAddress),
				Message: "Unsupported Gateway address, address type is not supported",
			},
			expectedProgrammed: &metav1.Condition{
				Type:    string(gatewayv1.GatewayConditionProgrammed),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.GatewayReasonInvalid),
				Message: "Address is not ready",
			},
		},
		{
			name: "empty address value",
			addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddressType,
					Value: "",
				},
			},
			expectedValid: false,
			expectedAccepted: &metav1.Condition{
				Type:    string(gatewayv1.GatewayConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.GatewayReasonUnsupportedAddress),
				Message: "Unsupported Gateway address, address value is not set",
			},
			expectedProgrammed: &metav1.Condition{
				Type:    string(gatewayv1.GatewayConditionProgrammed),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.GatewayReasonInvalid),
				Message: "Address is not ready",
			},
		},
		{
			name: "invalid ip address string",
			addresses: []gatewayv1.GatewaySpecAddress{
				{
					Type:  &ipAddressType,
					Value: "invalid-ip-999.999.999.999",
				},
			},
			expectedValid: false,
			expectedAccepted: &metav1.Condition{
				Type:    string(gatewayv1.GatewayConditionAccepted),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.GatewayReasonUnsupportedAddress),
				Message: "Unsupported Gateway address, invalid ip address",
			},
			expectedProgrammed: &metav1.Condition{
				Type:    string(gatewayv1.GatewayConditionProgrammed),
				Status:  metav1.ConditionFalse,
				Reason:  string(gatewayv1.GatewayReasonInvalid),
				Message: "Address is not ready",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewGatewayStatusManager(nil, hivetest.Logger(t))
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-gw",
					Namespace: "default",
				},
				Spec: gatewayv1.GatewaySpec{
					Addresses: tt.addresses,
				},
			}

			valid := m.validateStaticAddresses(gw)
			assert.Equal(t, tt.expectedValid, valid)

			if tt.expectedAccepted != nil {
				cond := meta.FindStatusCondition(gw.Status.Conditions, tt.expectedAccepted.Type)
				require.NotNil(t, cond)
				assert.Equal(t, tt.expectedAccepted.Status, cond.Status)
				assert.Equal(t, tt.expectedAccepted.Reason, cond.Reason)
				assert.Equal(t, tt.expectedAccepted.Message, cond.Message)
			}

			if tt.expectedProgrammed != nil {
				cond := meta.FindStatusCondition(gw.Status.Conditions, tt.expectedProgrammed.Type)
				require.NotNil(t, cond)
				assert.Equal(t, tt.expectedProgrammed.Status, cond.Status)
				assert.Equal(t, tt.expectedProgrammed.Reason, cond.Reason)
				assert.Equal(t, tt.expectedProgrammed.Message, cond.Message)
			}
		})
	}
}
