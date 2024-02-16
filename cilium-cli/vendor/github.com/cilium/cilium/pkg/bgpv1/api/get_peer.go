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

type BGPHandlerInParams struct {
	Controller *agent.Controller
}

func NewGetPeerHandler(c *agent.Controller) restapi.GetBgpPeersHandler {
	return &getPeerHandler{
		controller: c,
	}
}

type getPeerHandler struct {
	controller *agent.Controller
}

func (h *getPeerHandler) Handle(params restapi.GetBgpPeersParams) middleware.Responder {
	if h.controller == nil {
		return api.Error(http.StatusNotImplemented, agent.ErrBGPControlPlaneDisabled)
	}
	peers, err := h.controller.BGPMgr.GetPeers(params.HTTPRequest.Context())
	if err != nil {
		return api.Error(http.StatusInternalServerError, fmt.Errorf("failed to get peers: %w", err))
	}
	return restapi.NewGetBgpPeersOK().WithPayload(peers)
}
