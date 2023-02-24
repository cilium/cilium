// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/api"
)

// getBGPPeersHandler gets peering information from BGP controller
func getBGPPeersHandler(d *Daemon, params restapi.GetBgpPeersParams) middleware.Responder {
	peers, err := d.bgpControlPlaneController.BGPMgr.GetPeers(params.HTTPRequest.Context())
	if err != nil {
		msg := fmt.Errorf("failed to get peers, %w", err)
		return api.Error(http.StatusInternalServerError, msg)
	}
	return restapi.NewGetBgpPeersOK().WithPayload(peers)
}
