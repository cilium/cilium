// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicies

import (
	"github.com/go-openapi/runtime/middleware"

	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type getLRP struct {
	lrp *lrpHandler
}

func newGetLRPHandler(h *lrpHandler) GetLrpHandler {
	return getLRP{h}
}

func (h getLRP) Handle(params GetLrpParams) middleware.Responder {
	h.lrp.params.Log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /lrp request")
	return NewGetLrpOK().WithPayload(h.lrp.getLRPs())
}
