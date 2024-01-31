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

func NewGetRoutePoliciesHandler(c *agent.Controller) restapi.GetBgpRoutePoliciesHandler {
	return &getRoutePoliciesHandler{
		controller: c,
	}
}

type getRoutePoliciesHandler struct {
	controller *agent.Controller
}

func (h *getRoutePoliciesHandler) Handle(params restapi.GetBgpRoutePoliciesParams) middleware.Responder {
	if h.controller == nil {
		return api.Error(http.StatusNotImplemented, agent.ErrBGPControlPlaneDisabled)
	}

	policies, err := h.controller.BGPMgr.GetRoutePolicies(params.HTTPRequest.Context(), params)
	if err != nil {
		return api.Error(http.StatusInternalServerError, fmt.Errorf("failed to get route policies: %w", err))
	}
	return restapi.NewGetBgpRoutePoliciesOK().WithPayload(policies)
}
