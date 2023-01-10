// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/operator/server/restapi/operator"
)

type getHealthz struct {
	*Server
}

// NewGetHealthzHandler handles health requests.
func NewGetHealthzHandler(s *Server) operator.GetHealthzHandler {
	return &getHealthz{Server: s}
}

// Handle handles GET requests for /healthz .
func (h *getHealthz) Handle(params operator.GetHealthzParams) middleware.Responder {
	select {
	// only start serving the real health check once all systems all up and running
	case <-h.Server.allSystemsGo:
		if err := h.Server.checkStatus(); err != nil {
			log.WithError(err).Warn("Health check status")

			return operator.NewGetHealthzInternalServerError().WithPayload(err.Error())
		}
	default:
	}

	return operator.NewGetHealthzOK().WithPayload("ok")
}
