package main

import (
	"fmt"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/metrics"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/go-openapi/runtime/middleware"
)

type getMetrics struct {
	daemon *Daemon
}

// NewGetMetricsHandler returns the metrics handler
func NewGetMetricsHandler(d *Daemon) restapi.GetMetricsHandler {
	return &getMetrics{daemon: d}
}

func (h *getMetrics) Handle(params restapi.GetMetricsParams) middleware.Responder {
	metrics, err := metrics.DumpMetrics()
	if err != nil {
		return api.Error(
			restapi.GetMetricsInternalServerErrorCode,
			fmt.Errorf("Cannot gather metrics from daemon"))
	}

	return restapi.NewGetMetricsOK().WithPayload(metrics)
}
