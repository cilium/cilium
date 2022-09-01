// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package types

import (
	"testing"
)

func TestParseAddrCluster(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantErr bool
	}{
		{"valid bare IPv4 address", "10.0.0.1", false},
		{"invalid bare IPv4 address", "257.0.0.1", true},

		{"valid IPv4 address and valid cluster-id", "10.0.0.1@1", false},
		{"invalid IPv4 address and valid cluster-id", "257.0.0.1@1", true},
		{"valid IPv4 address and invalid cluster-id", "10.0.0.1@foo", true},
		{"valid IPv4 address and enpty cluster-id", "10.0.0.1@", true},

		{"valid bare IPv6 address", "a::1", false},
		{"invalid bare IPv6 address", "g::1", true},

		{"valid IPv6 address and valid cluster-id", "a::1@1", false},
		{"invalid IPv6 address and valid cluster-id", "g::1@1", true},
		{"valid IPv6 address and invalid cluster-id", "a::1@foo", true},
		{"valid IPv6 address and enpty cluster-id", "a::1@", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAddrCluster(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddrCluster() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}

	// Ensure bare IP address equals to ClusterID = 0
	if MustParseAddrCluster("10.0.0.1") != MustParseAddrCluster("10.0.0.1@0") {
		t.Errorf("ParseAddrCluster() returns different results for bare IP address and IP address with zero ClusterID")
		return
	}
}
