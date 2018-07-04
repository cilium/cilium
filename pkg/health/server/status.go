// Copyright 2017 Authors of Cilium
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
	. "github.com/cilium/cilium/api/v1/health/server/restapi/connectivity"
	"github.com/cilium/cilium/pkg/api"

	"github.com/go-openapi/runtime/middleware"
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
