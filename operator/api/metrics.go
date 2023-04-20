// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	opMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var MetricsHandlerCell = cell.Module(
	"metrics-handler",
	"Operator metrics HTTP handler",

	cell.Provide(newMetricsHandler),
)

type metricsHandler struct{}

func newMetricsHandler() metrics.GetMetricsHandler {
	return &metricsHandler{}
}

func (h *metricsHandler) Handle(params metrics.GetMetricsParams) middleware.Responder {
	m, err := opMetrics.DumpMetrics()
	if err != nil {
		return metrics.NewGetMetricsFailed()
	}

	return metrics.NewGetMetricsOK().WithPayload(m)
}
