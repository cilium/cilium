// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/node"
)

// Mock implementations of dependencies
type mockStatusCollector struct {
	statusResponse models.StatusResponse
}

func (m *mockStatusCollector) GetStatus(bool, bool) models.StatusResponse {
	return m.statusResponse
}

type mockServiceInterface struct {
	lastUpdatedTs time.Time
}

func (m *mockServiceInterface) GetLastUpdatedAt() time.Time {
	return m.lastUpdatedTs
}

type mockLocalNodeStore struct {
	node        *node.LocalNode
	returnError bool
}

func (m *mockLocalNodeStore) Get(ctx context.Context) (node.LocalNode, error) {
	if m.returnError {
		return node.LocalNode{}, assert.AnError
	}
	return *m.node, nil
}

func TestKubeproxyHealthzHandler(t *testing.T) {
	currentTs := time.Now()
	lastUpdatedTs := currentTs.Add(-2 * time.Minute)

	testCases := []struct {
		name                string
		status              string
		nodeIsBeingDeleted  bool
		nodeStoreReturnErr  bool
		expectedStatusCode  int
		expectedLastUpdated time.Time
	}{
		{
			name:                "healthy node",
			status:              models.StatusStateOk,
			nodeIsBeingDeleted:  false,
			nodeStoreReturnErr:  false,
			expectedStatusCode:  http.StatusOK,
			expectedLastUpdated: currentTs,
		},
		{
			name:                "node being deleted",
			status:              models.StatusStateOk,
			nodeIsBeingDeleted:  true,
			nodeStoreReturnErr:  false,
			expectedStatusCode:  http.StatusServiceUnavailable,
			expectedLastUpdated: lastUpdatedTs,
		},
		{
			name:                "unhealthy warning status",
			status:              models.StatusStateWarning,
			nodeIsBeingDeleted:  false,
			nodeStoreReturnErr:  false,
			expectedStatusCode:  http.StatusServiceUnavailable,
			expectedLastUpdated: lastUpdatedTs,
		},
		{
			name:                "unhealthy failure status",
			status:              models.StatusStateFailure,
			nodeIsBeingDeleted:  false,
			nodeStoreReturnErr:  false,
			expectedStatusCode:  http.StatusServiceUnavailable,
			expectedLastUpdated: lastUpdatedTs,
		},
		{
			name:                "unhealthy status and node being deleted",
			status:              models.StatusStateWarning,
			nodeIsBeingDeleted:  true,
			nodeStoreReturnErr:  false,
			expectedStatusCode:  http.StatusServiceUnavailable,
			expectedLastUpdated: lastUpdatedTs,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up mocks
			mockStatus := &mockStatusCollector{}
			mockStatus.statusResponse = models.StatusResponse{
				Cilium: &models.Status{
					State: tc.status,
				},
			}

			mockSvc := &mockServiceInterface{
				lastUpdatedTs: lastUpdatedTs,
			}

			mockNode := &mockLocalNodeStore{
				node: &node.LocalNode{
					Local: &node.LocalNodeInfo{IsBeingDeleted: tc.nodeIsBeingDeleted},
				},
				returnError: tc.nodeStoreReturnErr,
			}

			handler := kubeproxyHealthzHandler{
				statusCollector: mockStatus,
				localNode:       mockNode,
				lastUpdateAter:  mockSvc,
			}

			// Create request and recorder
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			recorder := httptest.NewRecorder()

			// Call handler
			handler.ServeHTTP(recorder, req)

			// Check response
			resp := recorder.Result()
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, tc.name+" testcase failed with unexpected status code")

			// Parse response body
			var respBody struct {
				LastUpdated string `json:"lastUpdated"`
				CurrentTime string `json:"currentTime"`
			}
			err := json.NewDecoder(resp.Body).Decode(&respBody)
			require.NoError(t, err)

			// For the time comparison, we just need to check if the timestamps match
			// in terms of which reference time they match (current vs lastUpdated)
			if tc.expectedStatusCode == http.StatusOK {
				// In OK state, lastUpdated should NOT contain lastUpdatedTs
				assert.NotContains(t, respBody.LastUpdated, lastUpdatedTs.Format("15:04:05"), tc.name+" testcase failed with unexpected lastUpdated value")
			} else {
				// In error states, lastUpdated should contain lastUpdatedTs
				assert.Contains(t, respBody.LastUpdated, lastUpdatedTs.Format("15:04:05"), tc.name+" testcase failed with unexpected lastUpdated value")
			}
		})
	}
}
