// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

type GetHealthzHandler struct {
	collector StatusCollector
}

func (h *GetHealthzHandler) Handle(params daemonapi.GetHealthzParams) middleware.Responder {
	brief := params.Brief != nil && *params.Brief
	requireK8sConnectivity := params.RequireK8sConnectivity != nil && *params.RequireK8sConnectivity

	// Check for BGP readiness headers
	requireBGPConnectivity := false
	bgpMode := "any"

	if params.HTTPRequest != nil && params.HTTPRequest.Header != nil {
		if bgpHeader := params.HTTPRequest.Header.Get("require-bgp-connectivity"); bgpHeader == "true" {
			requireBGPConnectivity = true
		}
		if modeHeader := params.HTTPRequest.Header.Get("bgp-readiness-mode"); modeHeader != "" {
			// Validate BGP mode
			if modeHeader == "any" || modeHeader == "all" {
				bgpMode = modeHeader
			} else {
				// Invalid mode, default to "any" for safety
				bgpMode = "any"
			}
		}
	}

	// Validate collector is available
	if h.collector == nil {
		// Return a failed status response instead of internal server error
		sr := models.StatusResponse{
			Cilium: &models.Status{
				State: models.StatusStateFailure,
				Msg:   "status collector not initialized",
			},
		}
		return daemonapi.NewGetHealthzOK().WithPayload(&sr)
	}

	// Use enhanced status method if BGP connectivity is required
	if requireBGPConnectivity {
		sr := h.collector.GetStatusWithBGP(brief, requireK8sConnectivity, requireBGPConnectivity, bgpMode)
		return daemonapi.NewGetHealthzOK().WithPayload(&sr)
	}

	// Use standard status method
	sr := h.collector.GetStatus(brief, requireK8sConnectivity)
	return daemonapi.NewGetHealthzOK().WithPayload(&sr)
}
