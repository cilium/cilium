// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestIsTLSPassthroughListenerConfigured(t *testing.T) {
	tests := []struct {
		name  string
		model Model
		want  bool
	}{
		{
			name:  "empty model",
			model: Model{},
			want:  false,
		},
		{
			name: "listener with routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"example.com"}}}},
				},
			},
			want: true,
		},
		{
			name: "listener without routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
				},
			},
			want: false,
		},
		{
			name: "mixed — one with routes, one without",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
					{Port: 8443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"example.com"}}}},
				},
			},
			want: true,
		},
		{
			name: "multiple listeners all without routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
					{Port: 8443},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.IsTLSPassthroughListenerConfigured())
		})
	}
}

func TestTLSPassthroughPorts(t *testing.T) {
	tests := []struct {
		name  string
		model Model
		want  []uint32
	}{
		{
			name:  "empty model",
			model: Model{},
			want:  nil,
		},
		{
			name: "listeners with routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 8443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"a.com"}}}},
					{Port: 443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"b.com"}}}},
				},
			},
			want: []uint32{443, 8443},
		},
		{
			name: "routeless listeners excluded",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
					{Port: 8443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"a.com"}}}},
					{Port: 9443},
				},
			},
			want: []uint32{8443},
		},
		{
			name: "all routeless",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
					{Port: 8443},
				},
			},
			want: nil,
		},
		{
			name: "duplicate ports deduplicated",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"a.com"}}}},
					{Port: 443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"b.com"}}}},
				},
			},
			want: []uint32{443},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.TLSPassthroughPorts())
		})
	}
}
