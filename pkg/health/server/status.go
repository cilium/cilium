// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"github.com/go-openapi/runtime/middleware"

	. "github.com/cilium/cilium/api/v1/health/server/restapi/connectivity"
	"github.com/cilium/cilium/pkg/api"
)

type getStatusCache struct {
	*Server
}

type putStatusProbe struct {
	*Server
}

// NewGetStatusHandler handles requests for cached connectivity status.
func NewGetStatusHandler(s *Server) GetStatusHandler {
	return &getStatusCache{Server: s}
}

// NewPutStatusProbeHandler handles requests for connectivity probes.
func NewPutStatusProbeHandler(s *Server) PutStatusProbeHandler {
	return &putStatusProbe{Server: s}
}

// Handle handles GET requests for /status .
func (h *getStatusCache) Handle(params GetStatusParams) middleware.Responder {
	log.Debug("Handling request for /status")

	return NewGetStatusOK().WithPayload(h.GetStatusResponse())
}

// Handle handles GET requests for /status/probe .
func (h *putStatusProbe) Handle(params PutStatusProbeParams) middleware.Responder {
	log.Debug("Handling request for /status/probe")

	status, err := h.FetchStatusResponse()
	if err != nil {
		return api.Error(PutStatusProbeFailedCode, err)
	}
	return NewPutStatusProbeOK().WithPayload(status)
}
