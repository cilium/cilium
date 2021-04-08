// Copyright 2017-2019 Authors of Cilium
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

package server

import (
	healthModels "github.com/cilium/cilium/api/v1/health/models"
	. "github.com/cilium/cilium/api/v1/health/server/restapi"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/client"

	"github.com/go-openapi/runtime/middleware"
)

type getHealthz struct {
	*Server
}

// NewGetHealthzHandler handles health requests.
func NewGetHealthzHandler(s *Server) GetHealthzHandler {
	return &getHealthz{Server: s}
}

func (h *getHealthz) getCiliumStatus() (*ciliumModels.StatusResponse, error) {
	resp, err := h.Daemon.GetHealthz(nil)
	if err != nil {
		return nil, client.Hint(err)
	}
	return resp.Payload, nil
}

// Handle handles GET requests for /healthz .
func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	log.Debug("Handling request for /healthz")

	ciliumStatus, err := h.getCiliumStatus()
	if err != nil {
		return api.Error(GetHealthzFailedCode, err)
	}
	load, err := dumpLoad()
	if err != nil {
		return api.Error(GetHealthzFailedCode, err)
	}

	sr := healthModels.HealthResponse{}
	if ciliumStatus != nil {
		sr.Cilium = *ciliumStatus
	}
	sr.Uptime = h.Server.DumpUptime()
	sr.SystemLoad = load
	return NewGetHealthzOK().WithPayload(&sr)
}
