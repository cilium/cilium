// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"github.com/go-openapi/runtime/middleware"

	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/datapath/types"
)

func NewNodeIDApiHandler(nodeIDHandler types.NodeIDHandler) daemonapi.GetNodeIdsHandler {
	return &nodeIDApiHandler{
		nodeIDHandler: nodeIDHandler,
	}
}

type nodeIDApiHandler struct {
	nodeIDHandler types.NodeIDHandler
}

func (h *nodeIDApiHandler) Handle(_ daemonapi.GetNodeIdsParams) middleware.Responder {
	dump := h.nodeIDHandler.DumpNodeIDs()
	return daemonapi.NewGetNodeIdsOK().WithPayload(dump)
}
