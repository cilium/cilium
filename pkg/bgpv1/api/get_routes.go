// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
)

func NewGetRoutesHandler(c *agent.Controller) restapi.GetBgpRoutesHandler {
	return &getRoutesHandler{
		controller: c,
	}
}

type getRoutesHandler struct {
	controller *agent.Controller
}

func (h *getRoutesHandler) Handle(params restapi.GetBgpRoutesParams) middleware.Responder {
	if h.controller == nil {
		return api.Error(http.StatusNotImplemented, agent.ErrBGPControlPlaneDisabled)
	}
	routes, err := h.controller.BGPMgr.GetRoutes(params.HTTPRequest.Context(), params)
	if err != nil {
		return api.Error(http.StatusInternalServerError, fmt.Errorf("failed to get routes: %w", err))
	}
	return restapi.NewGetBgpRoutesOK().WithPayload(routes)
}
