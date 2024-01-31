// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/clustermesh-apiserver/health"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var HealthAPIEndpointsCell = cell.Module(
	"health-api-endpoints",
	"ClusterMesh Health API Endpoints",

	syncstate.Cell,
	cell.Provide(healthEndpoints),
)

type healthParameters struct {
	cell.In

	SyncState syncstate.SyncState
	Logger    logrus.FieldLogger
}

func healthEndpoints(params healthParameters) []health.EndpointFunc {
	return []health.EndpointFunc{
		{
			Path: "/readyz",
			HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
				statusCode := http.StatusInternalServerError
				reply := "NotReady"

				if params.SyncState.Complete() {
					statusCode = http.StatusOK
					reply = "Ready"
				}
				w.WriteHeader(statusCode)
				if _, err := w.Write([]byte(reply)); err != nil {
					params.Logger.WithError(err).Error("Failed to respond to /readyz request")
				}
			},
		},
	}
}
