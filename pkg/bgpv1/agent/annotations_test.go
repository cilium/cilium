// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"errors"
	"testing"
)

// TestAnnotation performs a series of unit tests ensuring the parsing of
// annotations works correctly.
func TestAnnotation(t *testing.T) {
	table := []struct {
		// name of test case
		name string
		// annotation key
		key string
		// annotation value
		value string
		// expected parsed attributes
		attr Attributes
		// expected parsed asn
		asn int64
		// error nil or not
		error error
	}{
		{
			name:  "Invalid key prefix",
			key:   "cilium.io/bpf-virtual-router.123",
			attr:  Attributes{},
			error: ErrNotVRouterAnno{"cilium.io/bpf-virtual-router.123"},
		},
		{
			name:  "No ASN",
			key:   "cilium.io/bgp-virtual-router..",
			attr:  Attributes{},
			error: ErrNoASNAnno{"cilium.io/bgp-virtual-router.."},
		},
		{
			name:  "Over 32bit ASN",
			key:   "cilium.io/bgp-virtual-router.4294967296",
			attr:  Attributes{},
			error: ErrASNAnno{"could not parse ASN as a 32bit integer", "4294967296", "cilium.io/bgp-virtual-router.4294967296"},
		},
		{
			name:  "Valid router-id",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "router-id=127.0.0.1",
			attr: Attributes{
				RouterID: "127.0.0.1",
			},
			asn:   123,
			error: nil,
		},
		{
			// This case is valid standard-wise, but we don't support it.
			name:  "Invalid decimal router-id",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "router-id=12345",
			attr:  Attributes{},
			error: ErrAttrib{"cilium.io/bgp-virtual-router.123", "router-id", "could not parse router-id as an IPv4 address"},
		},
		{
			name:  "Invalid non-IPv4-ish router-id",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "router-id=fd00::1",
			attr:  Attributes{},
			error: ErrAttrib{"cilium.io/bgp-virtual-router.123", "router-id", "router-id must be a valid IPv4 address"},
		},
		{
			name:  "Valid local-port",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "local-port=179",
			attr: Attributes{
				LocalPort: 179,
			},
			asn:   123,
			error: nil,
		},
		{
			name:  "Over 16bit local-port",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "local-port=65536",
			attr:  Attributes{},
			error: ErrAttrib{"cilium.io/bgp-virtual-router.123", "local-port", "could not parse into port number as 16bit integer"},
		},
		{
			name:  "Test parsing of router-id and local-port",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "router-id=127.0.0.1,local-port=179",
			attr: Attributes{
				RouterID:  "127.0.0.1",
				LocalPort: 179,
			},
			asn:   123,
			error: nil,
		},
		{
			name:  "Empty attributes is not an error",
			key:   "cilium.io/bgp-virtual-router.123",
			attr:  Attributes{},
			asn:   123,
			error: nil,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			asn, attr, err := parseAnnotation(tt.key, tt.value)
			if asn != tt.asn {
				t.Fatalf("got: %v, want: %v", asn, tt.asn)
			}
			if attr.RouterID != tt.attr.RouterID {
				t.Fatalf("got: %v, want: %v", attr.RouterID, tt.attr.RouterID)
			}
			if attr.LocalPort != tt.attr.LocalPort {
				t.Fatalf("got: %v, want: %v", attr.LocalPort, tt.attr.LocalPort)
			}
			if !errors.Is(err, tt.error) {
				t.Fatalf("got: %v, want: %v", err, tt.error)
			}
		})
	}
}

func TestResolveRouterID(t *testing.T) {
	t.Run("RouterID specified", func(t *testing.T) {
		annoMap, err := NewAnnotationMap(map[string]string{
			"cilium.io/bgp-virtual-router.123": "router-id=127.0.0.1",
		})
		if err != nil {
			t.Fatal(err)
		}

		routerID, err := annoMap.ResolveRouterID(123)
		if err != nil {
			t.Fatal(err)
		}

		if routerID != "127.0.0.1" {
			t.Fatalf("got: %v, want: %v", routerID, "127.0.0.1")
		}
	})

	t.Run("RouterID unspecified", func(t *testing.T) {
		annoMap, err := NewAnnotationMap(map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = annoMap.ResolveRouterID(123)
		if err == nil {
			t.Fatal("expected error, got no error")
		}
	})
}

func BenchmarkErrNotVRouterAnnoError(b *testing.B) {
	e := &ErrNotVRouterAnno{
		a: "foo error",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Error()
	}
}

func BenchmarkErrErrNoASNAnno(b *testing.B) {
	e := &ErrNoASNAnno{
		a: "foo error",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Error()
	}
}

func BenchmarkErrASNAnno(b *testing.B) {
	e := &ErrASNAnno{
		err:  "foo error",
		asn:  "foo asn",
		anno: "foo anno",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Error()
	}
}
