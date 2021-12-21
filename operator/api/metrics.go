// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package api

import (
	"github.com/cilium/cilium/api/v1/operator/server/restapi/metrics"
	opMetrics "github.com/cilium/cilium/operator/metrics"

	"github.com/go-openapi/runtime/middleware"
)

type getMetrics struct {
	*Server
}

// NewGetMetricsHandler handles metrics requests.
func NewGetMetricsHandler(s *Server) metrics.GetMetricsHandler {
	return &getMetrics{Server: s}
}

// Handle handles GET requests for /metrics/ .
func (h *getMetrics) Handle(params metrics.GetMetricsParams) middleware.Responder {
	m, err := opMetrics.DumpMetrics()
	if err != nil {
		return metrics.NewGetMetricsFailed()
	}

	return metrics.NewGetMetricsOK().WithPayload(m)
}
