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

func TestModel_IsAccessLogsConfigured(t *testing.T) {
	tests := []struct {
		name  string
		model *Model
		want  bool
	}{
		{
			name:  "model is nil",
			model: nil,
			want:  false,
		},
		{
			name:  "model is empty",
			model: &Model{},
			want:  false,
		},
		{
			name: "telemetry is nil",
			model: &Model{
				Telemetry: nil,
			},
			want: false,
		},
		{
			name: "telemetry is empty",
			model: &Model{
				Telemetry: nil,
			},
			want: false,
		},
		{
			name: "access logs are nil",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: nil,
				},
			},
			want: false,
		},
		{
			name: "access logs are empty",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{},
				},
			},
			want: false,
		},
		{
			name: "access logs are configured with text format",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetHTTP: {
							{
								Format: AccessLogsFormatText,
								Text:   "%LOG_FORMAT%",
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "access logs are configured with json format",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetTCP: {
							{
								Format: AccessLogsFormatJSON,
								JSON: map[string]string{
									"log_format": "%LOG_FORMAT%",
								},
							},
						},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.model.IsAccessLogsConfigured(); got != tt.want {
				t.Errorf("Model.IsAccessLogsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModel_IsHTTPAccessLogsConfigured(t *testing.T) {
	tests := []struct {
		name  string
		model *Model
		want  bool
	}{
		{
			name:  "model is nil",
			model: nil,
			want:  false,
		},
		{
			name:  "model is empty",
			model: &Model{},
			want:  false,
		},
		{
			name: "access logs are nil",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: nil,
				},
			},
			want: false,
		},
		{
			name: "access logs are empty",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{},
				},
			},
			want: false,
		},
		{
			name: "access logs only target tcp",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetTCP: {{}},
					},
				},
			},
			want: false,
		},
		{
			name: "access logs target http",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetHTTP: {{}},
					},
				},
			},
			want: true,
		},
		{
			name: "access logs target http and tcp",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetTCP:  {{}},
						AccessLogsTargetHTTP: {{}},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.model.IsHTTPAccessLogsConfigured(); got != tt.want {
				t.Errorf("Model.IsHTTPAccessLogsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModel_IsTCPAccessLogsConfigured(t *testing.T) {
	tests := []struct {
		name  string
		model *Model
		want  bool
	}{
		{
			name:  "model is nil",
			model: nil,
			want:  false,
		},
		{
			name:  "model is empty",
			model: &Model{},
			want:  false,
		},
		{
			name: "access logs are nil",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: nil,
				},
			},
			want: false,
		},
		{
			name: "access logs are empty",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{},
				},
			},
			want: false,
		},
		{
			name: "access logs only target http",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetHTTP: {{}},
					},
				},
			},
			want: false,
		},
		{
			name: "access logs target tcp",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetTCP: {{}},
					},
				},
			},
			want: true,
		},
		{
			name: "access logs target http and tcp",
			model: &Model{
				Telemetry: &Telemetry{
					AccessLogs: map[AccessLogsTarget][]AccessLogs{
						AccessLogsTargetHTTP: {{}},
						AccessLogsTargetTCP:  {{}},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.model.IsTCPAccessLogsConfigured(); got != tt.want {
				t.Errorf("Model.IsTCPAccessLogsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}
