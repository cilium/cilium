// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestValidateTLSOptions(t *testing.T) {
	manager := &ListenerStatusManager{}
	tests := []struct {
		name        string
		options     map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue
		passthrough bool
		wantErr     bool
	}{
		{
			name: "no options set",
		},
		{
			name: "min only",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "1.3",
			},
		},
		{
			name: "max only",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMaxVersion: "1.2",
			},
		},
		{
			name: "ignores other domains",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				"example.com/tls-option": "foo",
			},
		},
		{
			name: "supported options",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "1.2",
				model.TLSOptionsMaxVersion: "1.3",
			},
		},
		{
			name: "unknown option",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				"cilium.io/unknown-option": "foo",
			},
			wantErr: true,
		},
		{
			name: "unsupported version",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "2.0",
			},
			wantErr: true,
		},
		{
			name: "min bigger than max",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "1.3",
				model.TLSOptionsMaxVersion: "1.2",
			},
			wantErr: true,
		},
		{
			name: "min equal max",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "1.2",
				model.TLSOptionsMaxVersion: "1.2",
			},
		},
		{
			name: "min less max",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "1.2",
				model.TLSOptionsMaxVersion: "1.3",
			},
		},
		{
			name: "passthrough rejects supported Cilium option",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				model.TLSOptionsMinVersion: "1.3",
			},
			passthrough: true,
			wantErr:     true,
		},
		{
			name: "passthrough rejects unknown Cilium option",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				"cilium.io/unknown-option": "foo",
			},
			passthrough: true,
			wantErr:     true,
		},
		{
			name: "passthrough ignores other domains",
			options: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{
				"example.com/tls-option": "foo",
			},
			passthrough: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := gatewayv1.Listener{
				Name:     "test",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				TLS:      &gatewayv1.ListenerTLSConfig{Options: tt.options},
			}
			if tt.passthrough {
				mode := gatewayv1.TLSModePassthrough
				listener.Protocol = gatewayv1.TLSProtocolType
				listener.TLS.Mode = &mode
			}
			err := manager.validateTLSOptions(&listener)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}
