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
		asn int
		// error nil or not
		error error
	}{
		{
			name:  "Test parsing of router-id",
			key:   "cilium.io/bgp-virtual-router.123",
			value: "router-id=127.0.0.1",
			attr: Attributes{
				RouterID: "127.0.0.1",
			},
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
			if !errors.Is(err, tt.error) {
				t.Fatalf("got: %v, want: %v", err, tt.error)
			}
		})
	}
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
