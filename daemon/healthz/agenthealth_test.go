// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
)

type recordingStatusCollector struct {
	gotBrief                  bool
	gotRequireK8sConnectivity bool
	fn                        func(brief bool, requireK8sConnectivity bool) models.StatusResponse
}

func (r *recordingStatusCollector) GetStatus(brief bool, requireK8sConnectivity bool) models.StatusResponse {
	r.gotBrief = brief
	r.gotRequireK8sConnectivity = requireK8sConnectivity
	return r.fn(brief, requireK8sConnectivity)
}

func TestAgentHealthHandlerRequireK8sConnectivity(t *testing.T) {
	tests := []struct {
		name               string
		defaultRequireK8s  bool
		headerValue        string
		expectedRequireK8s bool
		expectedStatusCode int
	}{
		{
			name:               "header false ignores k8s staleness",
			defaultRequireK8s:  true,
			headerValue:        "false",
			expectedRequireK8s: false,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "header true fails on k8s staleness",
			defaultRequireK8s:  false,
			headerValue:        "true",
			expectedRequireK8s: true,
			expectedStatusCode: http.StatusServiceUnavailable,
		},
		{
			name:               "missing header uses config default true",
			defaultRequireK8s:  true,
			headerValue:        "",
			expectedRequireK8s: true,
			expectedStatusCode: http.StatusServiceUnavailable,
		},
		{
			name:               "invalid header falls back to config default false",
			defaultRequireK8s:  false,
			headerValue:        "not-a-bool",
			expectedRequireK8s: false,
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			collector := &recordingStatusCollector{
				fn: func(_ bool, requireK8sConnectivity bool) models.StatusResponse {
					if requireK8sConnectivity {
						return models.StatusResponse{
							Cilium: &models.Status{
								State: models.StatusStateWarning,
								Msg:   "Stale status data",
							},
						}
					}
					return models.StatusResponse{
						Cilium: &models.Status{
							State: models.StatusStateOk,
						},
					}
				},
			}

			handler := &agentHealthHandler{
				logger: hivetest.Logger(t),
				config: agentHealthConfig{
					AgentHealthRequireK8sConnectivity: tc.defaultRequireK8s,
				},
				statusCollector: collector,
			}

			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			if tc.headerValue != "" {
				req.Header.Set("require-k8s-connectivity", tc.headerValue)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.True(t, collector.gotBrief)
			assert.Equal(t, tc.expectedRequireK8s, collector.gotRequireK8sConnectivity)
			assert.Equal(t, tc.expectedStatusCode, rec.Code)
		})
	}
}
