// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/metrics"
	"github.com/cilium/cilium/pkg/api"
)

type metricsRestApiHandler struct{}

func newMetricsRestApiHandler() restapi.GetMetricsHandler {
	return &metricsRestApiHandler{}
}

func (h *metricsRestApiHandler) Handle(params restapi.GetMetricsParams) middleware.Responder {
	metrics, err := dumpMetrics()
	if err != nil {
		return api.Error(
			restapi.GetMetricsInternalServerErrorCode,
			fmt.Errorf("cannot gather metrics from daemon"))
	}

	return restapi.NewGetMetricsOK().WithPayload(metrics)
}
