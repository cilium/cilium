// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"github.com/go-openapi/runtime/middleware"

	healthModels "github.com/cilium/cilium/api/v1/health/models"
	. "github.com/cilium/cilium/api/v1/health/server/restapi"
	ciliumModels "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/client"
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
