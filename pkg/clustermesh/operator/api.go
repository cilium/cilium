// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/operator/server/restapi/cluster"
)

func newAPIClustersHandler(cm *clusterMesh) restapi.GetClusterHandler {
	return &clustersHandler{cm}
}

// REST API handler for the '/cluster' path to expose the list of
// remote clusters and their status.
type clustersHandler struct{ cm *clusterMesh }

func (h *clustersHandler) Handle(params restapi.GetClusterParams) middleware.Responder {
	var status []*models.RemoteCluster
	if h.cm != nil {
		status = h.cm.status()
	}

	return restapi.NewGetClusterOK().WithPayload(status)
}
