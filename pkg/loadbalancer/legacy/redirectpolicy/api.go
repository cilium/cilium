// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type getLrpHandler struct {
	lrpManager *Manager
}

func (h *getLrpHandler) Handle(params service.GetLrpParams) middleware.Responder {
	h.lrpManager.logger.Debug("GET /lrp request", logfields.Params, params)
	return service.NewGetLrpOK().WithPayload(getLRPs(h.lrpManager))
}

func getLRPs(rpm *Manager) []*models.LRPSpec {
	lrps := rpm.GetLRPs()
	list := make([]*models.LRPSpec, 0, len(lrps))
	for _, v := range lrps {
		list = append(list, v.GetModel())
	}
	return list
}
