// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/cilium/cilium/api/v1/models"

	. "gopkg.in/check.v1"
)

// 'check' testing suite scaffolding.
type KubeProxyHealthzTestSuite struct{}

var _ = Suite(&KubeProxyHealthzTestSuite{})

// Injected fake service.
type FakeService struct {
	injectedCurrentTs     time.Time
	injectedLastUpdatedTs time.Time
}

func (s *FakeService) GetCurrentTs() time.Time {
	return s.injectedCurrentTs
}

func (s *FakeService) GetLastUpdatedTs() time.Time {
	return s.injectedLastUpdatedTs
}

// Injected fake daemon.
type FakeDaemon struct {
	injectedStatusResponse models.StatusResponse
}

func (d *FakeDaemon) getStatus(blah bool) models.StatusResponse {
	return d.injectedStatusResponse
}

type healthzPayload struct {
	LastUpdated string
	CurrentTime string
}

func (s *KubeProxyHealthzTestSuite) TestKubeProxyHealth(c *C) {
	s.healthTestHelper(c, models.StatusStateOk, http.StatusOK, true)
	s.healthTestHelper(c, models.StatusStateWarning,
		http.StatusServiceUnavailable, false)
	s.healthTestHelper(c, models.StatusStateFailure,
		http.StatusServiceUnavailable, false)
}

func (s *KubeProxyHealthzTestSuite) healthTestHelper(c *C, ciliumStatus string,
	expectedHttpStatus int, testcasepositive bool) {
	var lastUpdateTs, currentTs, expectedTs time.Time
	lastUpdateTs = time.Unix(100, 0) // Fake 100 seconds after Unix.
	currentTs = time.Unix(200, 0)    // Fake 200 seconds after Unix.
	expectedTs = lastUpdateTs
	if testcasepositive {
		expectedTs = currentTs
	}
	// Create handler with injected behavior.
	h := kubeproxyHealthzHandler{
		d: &FakeDaemon{injectedStatusResponse: models.StatusResponse{
			Cilium: &models.Status{State: ciliumStatus}}},
		svc: &FakeService{
			injectedCurrentTs:     currentTs,
			injectedLastUpdatedTs: lastUpdateTs}}

	// Create a new request.
	req, err := http.NewRequest("GET", "/healthz", nil)
	c.Assert(err, IsNil)
	w := httptest.NewRecorder()

	// Serve.
	h.ServeHTTP(w, req)

	// Main return code meets expectations.
	c.Assert(w.Code, Equals, expectedHttpStatus,
		Commentf("expected status code %v, got %v", expectedHttpStatus, w.Code))

	// Timestamps meet expectations.
	var payload healthzPayload
	c.Assert(json.Unmarshal(w.Body.Bytes(), &payload), IsNil)
	layout := "2006-01-02 15:04:05 -0700 MST"
	lastUpdateTs, err = time.Parse(layout, payload.LastUpdated)
	c.Assert(err, IsNil)

	_, err = time.Parse(layout, payload.CurrentTime)
	c.Assert(err, IsNil)
	c.Assert(lastUpdateTs.Equal(expectedTs), Equals, true)
}
