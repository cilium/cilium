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

func TestHTTPSPortsSorted(t *testing.T) {
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
			name: "no HTTPS listeners",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 80},
					{Port: 8080},
				},
			},
			want: nil,
		},
		{
			name: "single HTTPS port",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: []uint32{443},
		},
		{
			name: "two HTTPS ports sorted",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 8443, TLS: []TLSSecret{{Name: "cert-b", Namespace: "ns"}}},
					{Port: 443, TLS: []TLSSecret{{Name: "cert-a", Namespace: "ns"}}},
				},
			},
			want: []uint32{443, 8443},
		},
		{
			name: "mixed HTTP and HTTPS",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 80},
					{Port: 443, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
					{Port: 8080},
					{Port: 50051, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: []uint32{443, 50051},
		},
		{
			name: "duplicate HTTPS ports deduplicated",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "a.com", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
					{Port: 443, Hostname: "b.com", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: []uint32{443},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.HTTPSPortsSorted())
		})
	}
}

func TestNeedsPerPortHTTPSListeners(t *testing.T) {
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
			name: "one HTTPS port",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: false,
		},
		{
			name: "two HTTPS ports",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
					{Port: 50051, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: true,
		},
		{
			name: "HTTP only",
			model: Model{
				HTTP: []HTTPListener{{Port: 80}, {Port: 8080}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.NeedsPerPortHTTPSListeners())
		})
	}
}

func TestIsHTTPSPortConfigured(t *testing.T) {
	m := Model{
		HTTP: []HTTPListener{
			{Port: 80},
			{Port: 443, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
			{Port: 50051, TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
		},
	}
	assert.True(t, m.IsHTTPSPortConfigured(443))
	assert.True(t, m.IsHTTPSPortConfigured(50051))
	assert.False(t, m.IsHTTPSPortConfigured(80))
	assert.False(t, m.IsHTTPSPortConfigured(9999))
}

func TestTLSSecretsToListeners(t *testing.T) {
	certA := TLSSecret{Name: "cert-a", Namespace: "ns"}
	certB := TLSSecret{Name: "cert-b", Namespace: "ns"}

	m := Model{
		HTTP: []HTTPListener{
			{Port: 443, Hostname: "a.com", TLS: []TLSSecret{certA}},
			{Port: 50051, Hostname: "a.com", TLS: []TLSSecret{certA}},
			{Port: 8443, Hostname: "b.com", TLS: []TLSSecret{certB}},
		},
	}

	got := m.TLSSecretsToListeners()

	assert.ElementsMatch(t, []TLSListenerRef{
		{Hostname: "a.com", Port: 443},
		{Hostname: "a.com", Port: 50051},
	}, got[certA])

	assert.ElementsMatch(t, []TLSListenerRef{
		{Hostname: "b.com", Port: 8443},
	}, got[certB])

	assert.Len(t, got, 2)
}
