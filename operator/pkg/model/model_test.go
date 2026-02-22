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

func TestModel_TLSSecretsToHostnamesWithValidation_SharedSecretDifferentValidation(t *testing.T) {
	secret := TLSSecret{Name: "server-cert", Namespace: "default"}
	validOnly := &FrontendTLSValidation{
		CACertRefs: []FullyQualifiedResource{
			{Kind: "ConfigMap", Namespace: "default", Name: "ca-valid-only"},
		},
		RequireClientCertificate: true,
	}
	insecureFallback := &FrontendTLSValidation{
		CACertRefs: []FullyQualifiedResource{
			{Kind: "ConfigMap", Namespace: "default", Name: "ca-fallback"},
		},
		RequireClientCertificate: false,
	}

	m := &Model{
		HTTP: []HTTPListener{
			{
				Hostname:              "a.example.com",
				TLS:                   []TLSSecret{secret},
				FrontendTLSValidation: validOnly,
			},
			{
				Hostname:              "b.example.com",
				TLS:                   []TLSSecret{secret},
				FrontendTLSValidation: insecureFallback,
			},
		},
	}

	got := m.TLSSecretsToHostnamesWithValidation()
	if len(got) != 2 {
		t.Fatalf("expected 2 grouped entries, got %d", len(got))
	}

	gotByValidation := make(map[string]TLSSecretListenerData, len(got))
	for _, entry := range got {
		if entry.TLSSecret != secret {
			t.Fatalf("unexpected TLS secret: %+v", entry.TLSSecret)
		}
		gotByValidation[frontendTLSValidationKey(entry.FrontendTLSValidation)] = entry
	}

	validOnlyEntry, ok := gotByValidation[frontendTLSValidationKey(validOnly)]
	if !ok {
		t.Fatalf("missing valid-only group: %+v", gotByValidation)
	}
	if !reflect.DeepEqual(validOnlyEntry.Hostnames, []string{"a.example.com"}) {
		t.Fatalf("unexpected hostnames for valid-only group: %+v", validOnlyEntry.Hostnames)
	}

	insecureEntry, ok := gotByValidation[frontendTLSValidationKey(insecureFallback)]
	if !ok {
		t.Fatalf("missing insecure-fallback group: %+v", gotByValidation)
	}
	if !reflect.DeepEqual(insecureEntry.Hostnames, []string{"b.example.com"}) {
		t.Fatalf("unexpected hostnames for insecure-fallback group: %+v", insecureEntry.Hostnames)
	}
}

func TestModel_TLSSecretsToHostnamesWithValidation_SharedSecretSameValidation(t *testing.T) {
	secret := TLSSecret{Name: "server-cert", Namespace: "default"}
	validation := &FrontendTLSValidation{
		CACertRefs: []FullyQualifiedResource{
			{Kind: "ConfigMap", Namespace: "default", Name: "client-ca"},
		},
		RequireClientCertificate: true,
	}

	m := &Model{
		HTTP: []HTTPListener{
			{
				Hostname:              "b.example.com",
				TLS:                   []TLSSecret{secret},
				FrontendTLSValidation: validation,
			},
			{
				Hostname:              "a.example.com",
				TLS:                   []TLSSecret{secret},
				FrontendTLSValidation: validation,
			},
		},
	}

	got := m.TLSSecretsToHostnamesWithValidation()
	if len(got) != 1 {
		t.Fatalf("expected 1 grouped entry, got %d", len(got))
	}

	if got[0].TLSSecret != secret {
		t.Fatalf("unexpected TLS secret: %+v", got[0].TLSSecret)
	}
	if !reflect.DeepEqual(got[0].Hostnames, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("unexpected hostnames: %+v", got[0].Hostnames)
	}
	if !reflect.DeepEqual(got[0].FrontendTLSValidation, validation) {
		t.Fatalf("unexpected frontend validation: %+v", got[0].FrontendTLSValidation)
	}
}

func TestModel_TLSSecretsToHostnamesWithValidation_DeterministicOrder(t *testing.T) {
	listeners := []HTTPListener{
		{
			Hostname: "b.example.com",
			TLS:      []TLSSecret{{Name: "shared-cert", Namespace: "default"}},
			FrontendTLSValidation: &FrontendTLSValidation{
				CACertRefs: []FullyQualifiedResource{
					{Kind: "ConfigMap", Namespace: "default", Name: "ca-fallback"},
				},
				RequireClientCertificate: false,
			},
		},
		{
			Hostname: "a.example.com",
			TLS:      []TLSSecret{{Name: "shared-cert", Namespace: "default"}},
			FrontendTLSValidation: &FrontendTLSValidation{
				CACertRefs: []FullyQualifiedResource{
					{Kind: "ConfigMap", Namespace: "default", Name: "ca-valid-only"},
				},
				RequireClientCertificate: true,
			},
		},
		{
			Hostname: "z.example.com",
			TLS:      []TLSSecret{{Name: "other-cert", Namespace: "default"}},
			FrontendTLSValidation: &FrontendTLSValidation{
				CACertRefs: []FullyQualifiedResource{
					{Kind: "ConfigMap", Namespace: "default", Name: "ca-other"},
				},
				RequireClientCertificate: true,
			},
		},
	}

	got1 := (&Model{HTTP: listeners}).TLSSecretsToHostnamesWithValidation()
	got2 := (&Model{HTTP: []HTTPListener{listeners[2], listeners[0], listeners[1]}}).TLSSecretsToHostnamesWithValidation()

	if !reflect.DeepEqual(got1, got2) {
		t.Fatalf("expected deterministic output for reordered listeners.\nfirst:  %#v\nsecond: %#v", got1, got2)
	}
}
