// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/api"
)

// getBGPPeersHandler gets peering information from BGP controller
func getBGPPeersHandler(d *Daemon, params restapi.GetBgpPeersParams) middleware.Responder {
	if d.bgpControlPlaneController == nil {
		return api.Error(http.StatusNotImplemented, errors.New("BGP control plane disabled"))
	}
	peers, err := d.bgpControlPlaneController.BGPMgr.GetPeers(params.HTTPRequest.Context())
	if err != nil {
		msg := fmt.Errorf("failed to get peers: %w", err)
		return api.Error(http.StatusInternalServerError, msg)
	}
	return restapi.NewGetBgpPeersOK().WithPayload(peers)
}

// getBGPRoutesHandler gets BGP routes from BGP controller
func getBGPRoutesHandler(d *Daemon, params restapi.GetBgpRoutesParams) middleware.Responder {
	if d.bgpControlPlaneController == nil {
		return api.Error(http.StatusNotImplemented, errors.New("BGP control plane disabled"))
	}
	routes, err := d.bgpControlPlaneController.BGPMgr.GetRoutes(params.HTTPRequest.Context(), params)
	if err != nil {
		msg := fmt.Errorf("failed to get routes: %w", err)
		return api.Error(http.StatusInternalServerError, msg)
	}

	return restapi.NewGetBgpRoutesOK().WithPayload(routes)
}

// getBGPRoutePoliciesHandler gets BGP routing policies from BGP controller
func getBGPRoutePoliciesHandler(d *Daemon, params restapi.GetBgpRoutePoliciesParams) middleware.Responder {
	if d.bgpControlPlaneController == nil {
		return api.Error(http.StatusNotImplemented, errors.New("BGP control plane disabled"))
	}
	policies, err := d.bgpControlPlaneController.BGPMgr.GetRoutePolicies(params.HTTPRequest.Context(), params)
	if err != nil {
		msg := fmt.Errorf("failed to get route policies: %w", err)
		return api.Error(http.StatusInternalServerError, msg)
	}

	return restapi.NewGetBgpRoutePoliciesOK().WithPayload(policies)
}
