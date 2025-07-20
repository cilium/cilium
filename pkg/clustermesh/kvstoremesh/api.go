// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/kvstoremesh/server/restapi/cluster"
)

func newAPIClustersHandler(km *KVStoreMesh) restapi.GetClusterHandler {
	return &clustersHandler{km}
}

// REST API handler for the '/clusters' path to expose the list of
// remote clusters and their status.
type clustersHandler struct{ km *KVStoreMesh }

func (h *clustersHandler) Handle(params restapi.GetClusterParams) middleware.Responder {
	return restapi.NewGetClusterOK().WithPayload(h.km.status())
}
