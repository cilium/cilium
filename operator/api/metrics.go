// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	opMetrics "github.com/cilium/cilium/operator/metrics"
	ciliumMetrics "github.com/cilium/cilium/pkg/metrics"
)

var MetricsHandlerCell = cell.Module(
	"metrics-handler",
	"Operator metrics HTTP handler",

	cell.Provide(newMetricsHandler),
)

type metricsHandler struct {
	registry *ciliumMetrics.Registry
}

func newMetricsHandler(reg *ciliumMetrics.Registry) metrics.GetMetricsHandler {
	return &metricsHandler{registry: reg}
}

func (h *metricsHandler) Handle(params metrics.GetMetricsParams) middleware.Responder {
	m, err := opMetrics.DumpMetrics(h.registry)
	if err != nil {
		return metrics.NewGetMetricsFailed()
	}

	return metrics.NewGetMetricsOK().WithPayload(m)
}
