// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"fmt"
	"net/http"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	_ "github.com/cilium/cilium/pkg/hubble/metrics/dns"               // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/drop"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/flow"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/flows-to-world"    // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/http"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/icmp"              // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/kafka"             // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/policy"            // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/port-distribution" // invoke init
	_ "github.com/cilium/cilium/pkg/hubble/metrics/tcp"               // invoke init
)

var (
	enabledMetrics *api.Handlers
	registry       = prometheus.NewPedanticRegistry()
)

// ProcessFlow processes a flow and updates metrics
func ProcessFlow(ctx context.Context, flow *pb.Flow) error {
	if enabledMetrics != nil {
		return enabledMetrics.ProcessFlow(ctx, flow)
	}
	return nil
}

// initMetrics initialies the metrics system
func initMetrics(address string, enabled api.Map, grpcMetrics *grpc_prometheus.ServerMetrics, enableOpenMetrics bool) (<-chan error, error) {
	e, err := api.DefaultRegistry().ConfigureHandlers(registry, enabled)
	if err != nil {
		return nil, err
	}
	enabledMetrics = e

	registry.MustRegister(grpcMetrics)

	errChan := make(chan error, 1)

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			EnableOpenMetrics: enableOpenMetrics,
		}))
		srv := http.Server{
			Addr:    address,
			Handler: mux,
		}
		errChan <- srv.ListenAndServe()
	}()

	return errChan, nil
}

// EnableMetrics starts the metrics server with a given list of metrics. This is the
// function Cilium uses to configure Hubble metrics in embedded mode.
func EnableMetrics(log logrus.FieldLogger, metricsServer string, m []string, grpcMetrics *grpc_prometheus.ServerMetrics, enableOpenMetrics bool) error {
	errChan, err := initMetrics(metricsServer, api.ParseMetricList(m), grpcMetrics, enableOpenMetrics)
	if err != nil {
		return fmt.Errorf("unable to setup metrics: %v", err)
	}
	go func() {
		err := <-errChan
		if err != nil {
			log.WithError(err).Error("Unable to initialize metrics server")
		}
	}()
	return nil
}
