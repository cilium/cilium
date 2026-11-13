// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"reflect"
	"testing"

	clientgometrics "k8s.io/client-go/tools/metrics"
)

// TestClientGoMetricsUnregistered ensures importing the API types does not
// register Cilium's client-go metrics adapters as a side effect.
func TestClientGoMetricsUnregistered(t *testing.T) {
	tests := []struct {
		name     string
		adapter  any
		wantType string
	}{
		{"RequestResult", clientgometrics.RequestResult, "noopResult"},
		{"RequestLatency", clientgometrics.RequestLatency, "noopLatency"},
		{"RateLimiterLatency", clientgometrics.RateLimiterLatency, "noopLatency"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reflect.TypeOf(tt.adapter)
			if got == nil ||
				got.PkgPath() != "k8s.io/client-go/tools/metrics" ||
				got.Name() != tt.wantType {
				t.Fatalf("%s: expected client-go default %s, got %v",
					tt.name, tt.wantType, got)
			}
		})
	}
}
