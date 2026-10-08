// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"github.com/go-openapi/runtime/middleware"

	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
)

type GetHealthzHandler struct {
	collector StatusCollector
}

func (h *GetHealthzHandler) Handle(params daemonapi.GetHealthzParams) middleware.Responder {
	brief := params.Brief != nil && *params.Brief
	requireK8sConnectivity := params.RequireK8sConnectivity != nil && *params.RequireK8sConnectivity
	sr := h.collector.GetStatus(brief, requireK8sConnectivity)
	return daemonapi.NewGetHealthzOK().WithPayload(&sr)
}
