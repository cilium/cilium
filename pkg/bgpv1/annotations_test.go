// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package bgpv1

import "testing"

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
			if err != tt.error {
				t.Fatalf("got: %v, want: %v", err, tt.error)
			}
		})
	}
}
