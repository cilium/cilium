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

var testL4Listener = L4Listener{
	Name:     "test-l4-listener",
	Port:     8080,
	Protocol: L4ProtocolTCP,
}

var testL4Listener2 = L4Listener{
	Name:     "test-l4-listener2",
	Port:     8081,
	Protocol: L4ProtocolUDP,
}

func TestModel_GetListeners(t *testing.T) {
	type fields struct {
		HTTP []HTTPListener
		TLS  []TLSPassthroughListener
		L4   []L4Listener
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
				L4:   []L4Listener{testL4Listener, testL4Listener2},
			},
			want: []Listener{&testHTTPListener, &testHTTPListener2, &testTLSListener, &testTLSListener2, &testL4Listener, &testL4Listener2},
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
			name: "Only L4 listeners",
			fields: fields{
				L4: []L4Listener{testL4Listener, testL4Listener2},
			},
			want: []Listener{&testL4Listener, &testL4Listener2},
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
				L4:             tt.fields.L4,
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
			want: true,
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
			want: true,
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
			name: "routeless listeners and listeners with routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
					{Port: 8443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"a.com"}}}},
					{Port: 9443},
				},
			},
			want: []uint32{443, 8443, 9443},
		},
		{
			name: "all routeless",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443},
					{Port: 8443},
				},
			},
			want: []uint32{443, 8443},
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

func TestNeedsCrossProtocolSplit(t *testing.T) {
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
			name: "HTTPS only",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "api.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
			},
			want: false,
		},
		{
			name: "TLS passthrough only",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "api.example.test", Routes: []TLSPassthroughRoute{{Hostnames: []string{"api.example.test"}}}},
				},
			},
			want: false,
		},
		{
			name: "same hostname across protocols",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "api.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "api.example.test", Routes: []TLSPassthroughRoute{{Hostnames: []string{"api.example.test"}}}},
				},
			},
			want: true,
		},
		{
			name: "same hostname and port across protocols does not trigger per-port split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "api.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Hostname: "api.example.test", Routes: []TLSPassthroughRoute{{Hostnames: []string{"api.example.test"}}}},
				},
			},
			want: false,
		},
		{
			name: "disjoint hostnames across protocols",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "web.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "tls.example.test", Routes: []TLSPassthroughRoute{{Hostnames: []string{"tls.example.test"}}}},
				},
			},
			want: false,
		},
		{
			name: "overlap via route hostname",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "shared.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"shared.example.test"}}}},
				},
			},
			want: true,
		},
		{
			name: "catch-all hostnames on both protocols trigger split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "*", Routes: []TLSPassthroughRoute{{Hostnames: []string{"*"}}}},
				},
			},
			want: true,
		},
		{
			name: "empty catch-all hostnames on both protocols trigger split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "", Routes: []TLSPassthroughRoute{{Hostnames: []string{""}}}},
				},
			},
			want: true,
		},
		{
			name: "catch-all HTTPS with specific TLS passthrough hostname on same port does not collide",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Hostname: "*", Routes: []TLSPassthroughRoute{{Hostnames: []string{"tls.example.test"}}}},
				},
			},
			want: false,
		},
		{
			name: "catch-all HTTPS with specific TLS passthrough hostname on different ports triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "*", Routes: []TLSPassthroughRoute{{Hostnames: []string{"tls.example.test"}}}},
				},
			},
			want: true,
		},
		{
			name: "specific HTTPS with catch-all TLS passthrough hostname on same port does not collide",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "web.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Hostname: "*", Routes: []TLSPassthroughRoute{{Hostnames: []string{"*"}}}},
				},
			},
			want: false,
		},
		{
			name: "specific HTTPS with catch-all TLS passthrough hostname on different ports triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "web.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "*", Routes: []TLSPassthroughRoute{{Hostnames: []string{"*"}}}},
				},
			},
			want: true,
		},
		{
			name: "catch-all HTTPS with empty TLS passthrough route hostnames triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "tls.example.test", Routes: []TLSPassthroughRoute{{}}},
				},
			},
			want: true,
		},
		{
			name: "catch-all HTTPS with catch-all TLS route hostname triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Hostname: "tls.example.test", Routes: []TLSPassthroughRoute{{Hostnames: []string{"*"}}}},
				},
			},
			want: true,
		},
		{
			name: "HTTPS wildcard does not collide with TLS route exact hostname on same port",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"api.example.test"}}}},
				},
			},
			want: false,
		},
		{
			name: "HTTPS wildcard with TLS route exact hostname on different ports triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"api.example.test"}}}},
				},
			},
			want: true,
		},
		{
			name: "HTTPS wildcard does not collide with TLS route different suffix",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"api.example.org"}}}},
				},
			},
			want: false,
		},
		{
			name: "HTTPS exact hostname does not collide with TLS route wildcard on same port",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "api.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"*.example.test"}}}},
				},
			},
			want: false,
		},
		{
			name: "HTTPS exact hostname with TLS route wildcard on different ports triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "api.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"*.example.test"}}}},
				},
			},
			want: true,
		},
		{
			name: "same wildcard across protocols triggers split",
			model: Model{
				HTTP: []HTTPListener{
					{Port: 443, Hostname: "*.example.test", TLS: []TLSSecret{{Name: "cert", Namespace: "ns"}}},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{Port: 9443, Routes: []TLSPassthroughRoute{{Hostnames: []string{"*.example.test"}}}},
				},
			},
			want: true,
		},
		{
			name: "routeless TLS passthrough uses listener hostname for split detection",
			model: Model{
				HTTP: []HTTPListener{
					{
						Port:     443,
						Hostname: "shared.example.test",
						TLS:      []TLSSecret{{Name: "cert", Namespace: "ns"}},
					},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port:     9443,
						Hostname: "shared.example.test",
					},
				},
			},
			want: true,
		},
		{
			name: "routeful TLS passthrough uses route hostname for split detection",
			model: Model{
				HTTP: []HTTPListener{
					{
						Port:     443,
						Hostname: "web.example.test",
						TLS:      []TLSSecret{{Name: "cert", Namespace: "ns"}},
					},
				},
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port:     9443,
						Hostname: "*",
						Routes: []TLSPassthroughRoute{
							{Hostnames: []string{"tls.example.test"}},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.NeedsCrossProtocolSplit())
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

func TestHasTLSPassthroughListenerWithoutRoutes(t *testing.T) {
	tests := []struct {
		name  string
		model Model
		want  bool
	}{
		{
			name:  "no TLS passthrough listeners",
			model: Model{},
			want:  false,
		},
		{
			name: "TLS passthrough listener without routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{{Port: 443}},
			},
			want: true,
		},
		{
			name: "TLS passthrough route with backend",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port: 443,
						Routes: []TLSPassthroughRoute{
							{
								Backends: []Backend{{Name: "backend", Namespace: "default", Port: &BackendPort{Port: 443}}},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "TLS passthrough route without backends",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port:   443,
						Routes: []TLSPassthroughRoute{{Hostnames: []string{"example.com"}}},
					},
				},
			},
			want: false,
		},
		{
			name: "one TLS passthrough route without backends among valid routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port: 443,
						Routes: []TLSPassthroughRoute{
							{
								Backends: []Backend{{Name: "backend", Namespace: "default", Port: &BackendPort{Port: 443}}},
							},
						},
					},
					{
						Port:   8443,
						Routes: []TLSPassthroughRoute{{Hostnames: []string{"missing.example.com"}}},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.HasTLSPassthroughListenerWithoutRoutes())
		})
	}
}

func TestHasTLSPassthroughRouteWithoutBackends(t *testing.T) {
	tests := []struct {
		name  string
		model Model
		want  bool
	}{
		{
			name:  "no TLS passthrough listeners",
			model: Model{},
			want:  false,
		},
		{
			name: "TLS passthrough listener without routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{{Port: 443}},
			},
			want: false,
		},
		{
			name: "TLS passthrough route with backend",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port: 443,
						Routes: []TLSPassthroughRoute{
							{
								Backends: []Backend{{Name: "backend", Namespace: "default", Port: &BackendPort{Port: 443}}},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "TLS passthrough route without backends",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port:   443,
						Routes: []TLSPassthroughRoute{{Hostnames: []string{"example.com"}}},
					},
				},
			},
			want: true,
		},
		{
			name: "one TLS passthrough route without backends among valid routes",
			model: Model{
				TLSPassthrough: []TLSPassthroughListener{
					{
						Port: 443,
						Routes: []TLSPassthroughRoute{
							{
								Backends: []Backend{{Name: "backend", Namespace: "default", Port: &BackendPort{Port: 443}}},
							},
						},
					},
					{
						Port:   8443,
						Routes: []TLSPassthroughRoute{{Hostnames: []string{"missing.example.com"}}},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.model.HasTLSPassthroughRouteWithoutBackends())
		})
	}
}
