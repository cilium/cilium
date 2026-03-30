// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"reflect"
	"testing"
)

var testTLSListener = TLSPassthroughListener{
	Name: "test-tls-listener",
	Port: 443,
}

var testTLSListener2 = TLSPassthroughListener{
	Name: "test-tls-listener2",
	Port: 443,
}

var testHTTPListener = HTTPListener{
	Name: "test-http-listener",
	Port: 80,
}

var testHTTPListener2 = HTTPListener{
	Name: "test-http-listener2",
	Port: 80,
}

func TestModel_GetListeners(t *testing.T) {
	type fields struct {
		HTTP []HTTPListener
		TLS  []TLSPassthroughListener
	}
	tests := []struct {
		name   string
		fields fields
		want   []Listener
	}{
		{
			name: "Combine HTTP and TLS listeners",
			fields: fields{
				HTTP: []HTTPListener{testHTTPListener, testHTTPListener2},
				TLS:  []TLSPassthroughListener{testTLSListener, testTLSListener2},
			},
			want: []Listener{&testHTTPListener, &testHTTPListener2, &testTLSListener, &testTLSListener2},
		},
		{
			name: "Only HTTP listeners",
			fields: fields{
				HTTP: []HTTPListener{testHTTPListener, testHTTPListener2},
			},
			want: []Listener{&testHTTPListener, &testHTTPListener2},
		},
		{
			name: "Only TLS listeners",
			fields: fields{
				TLS: []TLSPassthroughListener{testTLSListener, testTLSListener2},
			},
			want: []Listener{&testTLSListener, &testTLSListener2},
		},
		{
			name:   "No listeners",
			fields: fields{},
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Model{
				HTTP:           tt.fields.HTTP,
				TLSPassthrough: tt.fields.TLS,
			}
			if got := m.GetListeners(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Model.GetListeners() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModel_IsCORSFilterConfigured(t *testing.T) {
	tests := []struct {
		name          string
		httpListeners []HTTPListener
		want          bool
	}{
		{
			name:          "no HTTP listeners",
			httpListeners: []HTTPListener{},
			want:          false,
		},
		{
			name: "HTTP listener without CORS",
			httpListeners: []HTTPListener{
				{Routes: []HTTPRoute{{CORS: nil}}},
			},
			want: false,
		},
		{
			name: "one HTTP listener with CORS",
			httpListeners: []HTTPListener{
				{Routes: []HTTPRoute{
					{
						CORS: &HTTPCORSFilter{
							AllowOrigins: []string{"*"},
						},
					},
				}},
			},
			want: true,
		},
		{
			name: "multiple HTTP listeners with one CORS filter",
			httpListeners: []HTTPListener{
				{Routes: []HTTPRoute{{CORS: nil}}},
				{Routes: []HTTPRoute{
					{
						CORS: &HTTPCORSFilter{
							AllowOrigins: []string{"*"},
						},
					},
				}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Model{
				HTTP: tt.httpListeners,
			}
			if got := m.IsCORSFilterConfigured(); got != tt.want {
				t.Errorf("Model.IsCORSFilterConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModel_GRPCWebTranslationEnabled(t *testing.T) {
	tests := []struct {
		name  string
		model *Model
		want  bool
	}{
		{
			name: "nil model",
			want: true,
		},
		{
			name:  "empty model",
			model: &Model{},
			want:  true,
		},
		{
			name: "nil grpc-web translation config",
			model: &Model{
				HTTPOptions: &HTTPOptions{},
			},
			want: true,
		},
		{
			name: "enabled",
			model: &Model{
				HTTPOptions: &HTTPOptions{
					GRPCWebTranslation: &GRPCWebTranslationConfig{
						Enabled: true,
					},
				},
			},
			want: true,
		},
		{
			name: "disabled",
			model: &Model{
				HTTPOptions: &HTTPOptions{
					GRPCWebTranslation: &GRPCWebTranslationConfig{
						Enabled: false,
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.model.GRPCWebTranslationEnabled(); got != tt.want {
				t.Errorf("Model.GRPCWebTranslationEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModel_GetForwardClientCertDetails(t *testing.T) {
	appendForward := "APPEND_FORWARD"

	tests := []struct {
		name  string
		model *Model
		want  *string
	}{
		{
			name: "nil model",
			want: nil,
		},
		{
			name:  "empty model",
			model: &Model{},
			want:  nil,
		},
		{
			name: "nil value in options",
			model: &Model{
				HTTPOptions: &HTTPOptions{},
			},
			want: nil,
		},
		{
			name: "value set in options",
			model: &Model{
				HTTPOptions: &HTTPOptions{
					ForwardClientCertDetails: &appendForward,
				},
			},
			want: &appendForward,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.model.GetForwardClientCertDetails()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Model.GetForwardClientCertDetails() = %v, want %v", got, tt.want)
			}
		})
	}
}
