// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/operator/models"
	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	"github.com/cilium/cilium/pkg/hive/cell"
	pkgMetrics "github.com/cilium/cilium/pkg/metrics"
)

var MetricsHandlerCell = cell.Module(
	"metrics-handler",
	"Operator metrics HTTP handler",

	cell.Provide(newMetricsHandler),
)

type metricsHandler struct {
	registry *pkgMetrics.Registry
}

func newMetricsHandler(r *pkgMetrics.Registry) metrics.GetMetricsHandler {
	return &metricsHandler{}
}

func (h *metricsHandler) Handle(params metrics.GetMetricsParams) middleware.Responder {
	dm, err := h.registry.DumpMetrics()
	if err != nil {
		return metrics.NewGetMetricsFailed()
	}

	var m []*models.Metric
	for _, metric := range dm {
		m = append(m, &models.Metric{
			Name:   metric.Name,
			Labels: metric.Labels,
			Value:  metric.Value,
		})
	}

	return metrics.NewGetMetricsOK().WithPayload(m)
}
