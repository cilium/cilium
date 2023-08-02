// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/api"
	bgpv1 "github.com/cilium/cilium/pkg/bgpv1/agent"
)

type getBGP struct {
	bgpController *bgpv1.Controller
}

// NewGetBGPHandler returns bgp peering status endpoint
func NewGetBGPHandler(c *bgpv1.Controller) restapi.GetBgpPeersHandler {
	return &getBGP{bgpController: c}
}

// Handle gets peering information from BGP controller
func (b *getBGP) Handle(params restapi.GetBgpPeersParams) middleware.Responder {
	if b.bgpController == nil {
		return api.Error(http.StatusNotImplemented, fmt.Errorf("BGP Control Plane disabled"))
	}
	peers, err := b.bgpController.BGPMgr.GetPeers(params.HTTPRequest.Context())
	if err != nil {
		msg := fmt.Errorf("failed to get peers: %w", err)
		return api.Error(http.StatusInternalServerError, msg)
	}

	return restapi.NewGetBgpPeersOK().WithPayload(peers)
}

type getBGPRoutes struct {
	bgpController *bgpv1.Controller
}

// NewGetBGPRoutesHandler returns bgp routes status endpoint
func NewGetBGPRoutesHandler(c *bgpv1.Controller) restapi.GetBgpRoutesHandler {
	return &getBGPRoutes{bgpController: c}
}

// Handle gets BGP routes from BGP controller
func (b *getBGPRoutes) Handle(params restapi.GetBgpRoutesParams) middleware.Responder {
	if b.bgpController == nil {
		return api.Error(http.StatusNotImplemented, fmt.Errorf("BGP Control Plane disabled"))
	}
	routes, err := b.bgpController.BGPMgr.GetRoutes(params.HTTPRequest.Context(), params)
	if err != nil {
		msg := fmt.Errorf("failed to get routes: %w", err)
		return api.Error(http.StatusInternalServerError, msg)
	}

	return restapi.NewGetBgpRoutesOK().WithPayload(routes)
}
