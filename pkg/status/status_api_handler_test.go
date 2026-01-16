// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

// mockStatusCollector is a mock implementation of the StatusCollector interface for testing.
type mockStatusCollector struct {
	getStatusCalled        bool
	getStatusWithBGPCalled bool
	lastBGPMode            string
	lastRequireBGP         bool
}

func (m *mockStatusCollector) GetStatus(brief bool, requireK8sConnectivity bool) models.StatusResponse {
	m.getStatusCalled = true
	return models.StatusResponse{}
}

func (m *mockStatusCollector) GetStatusWithBGP(brief bool, requireK8sConnectivity bool, requireBGPConnectivity bool, bgpMode string) models.StatusResponse {
	m.getStatusWithBGPCalled = true
	m.lastRequireBGP = requireBGPConnectivity
	m.lastBGPMode = bgpMode
	return models.StatusResponse{}
}

func TestGetHealthzHandler(t *testing.T) {
	tests := []struct {
		name                   string
		headers                http.Header
		expectedBGPMode        string
		expectGetStatusWithBGP bool
	}{
		{
			name:                   "no BGP headers",
			headers:                http.Header{},
			expectGetStatusWithBGP: false,
		},
		{
			name: "require BGP connectivity with default mode",
			headers: http.Header{
				"Require-Bgp-Connectivity": []string{"true"},
			},
			expectGetStatusWithBGP: true,
			expectedBGPMode:        "any",
		},
		{
			name: "require BGP connectivity with 'any' mode",
			headers: http.Header{
				"Require-Bgp-Connectivity": []string{"true"},
				"Bgp-Readiness-Mode":       []string{"any"},
			},
			expectGetStatusWithBGP: true,
			expectedBGPMode:        "any",
		},
		{
			name: "require BGP connectivity with 'all' mode",
			headers: http.Header{
				"Require-Bgp-Connectivity": []string{"true"},
				"Bgp-Readiness-Mode":       []string{"all"},
			},
			expectGetStatusWithBGP: true,
			expectedBGPMode:        "all",
		},
		{
			name: "invalid BGP mode defaults to 'any'",
			headers: http.Header{
				"Require-Bgp-Connectivity": []string{"true"},
				"Bgp-Readiness-Mode":       []string{"invalid-mode"},
			},
			expectGetStatusWithBGP: true,
			expectedBGPMode:        "any",
		},
		{
			name: "collector is nil",
			// This test case will be handled by setting the collector to nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCollector := &mockStatusCollector{}
			handler := &GetHealthzHandler{}

			if tt.name == "collector is nil" {
				handler.collector = nil
			} else {
				handler.collector = mockCollector
			}

			req := &http.Request{Header: tt.headers}
			params := daemonapi.GetHealthzParams{HTTPRequest: req}

			handler.Handle(params)

			if tt.name == "collector is nil" {
				// In this case, we don't expect any collector methods to be called.
				// The handler should return a failure status on its own.
				require.False(t, mockCollector.getStatusCalled, "GetStatus should not be called when collector is nil")
				require.False(t, mockCollector.getStatusWithBGPCalled, "GetStatusWithBGP should not be called when collector is nil")
				return
			}

			if tt.expectGetStatusWithBGP {
				require.True(t, mockCollector.getStatusWithBGPCalled, "expected GetStatusWithBGP to be called")
				require.False(t, mockCollector.getStatusCalled, "expected GetStatus not to be called")
				require.Equal(t, tt.expectedBGPMode, mockCollector.lastBGPMode, "unexpected BGP mode")
			} else {
				require.True(t, mockCollector.getStatusCalled, "expected GetStatus to be called")
				require.False(t, mockCollector.getStatusWithBGPCalled, "expected GetStatusWithBGP not to be called")
			}
		})
	}
}
