// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

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
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/time"
)

type CiliumEndpointDeletionHandler struct {
	gracefulPeriod time.Duration
	queue          workqueue.DelayingInterface
}

var (
	enabledMetrics          *api.Handlers
	registry                = prometheus.NewPedanticRegistry()
	endpointDeletionHandler *CiliumEndpointDeletionHandler
)

// Additional metrics - they're not counting flows, so are not served via
// Hubble metrics API, but belong to the same Prometheus namespace.
var (
	labelSource = "source"
	LostEvents  = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "lost_events_total",
		Help:      "Number of lost events",
	}, []string{labelSource})
)

// ProcessFlow processes a flow and updates metrics
func ProcessFlow(ctx context.Context, flow *pb.Flow) error {
	if enabledMetrics != nil {
		return enabledMetrics.ProcessFlow(ctx, flow)
	}
	return nil
}

func ProcessCiliumEndpointDeletion(pod *types.CiliumEndpoint) error {
	if endpointDeletionHandler != nil && enabledMetrics != nil {
		endpointDeletionHandler.queue.AddAfter(pod, endpointDeletionHandler.gracefulPeriod)
	}
	return nil
}

func initMetricHandlers(enabled api.Map) (*api.Handlers, error) {
	return api.DefaultRegistry().ConfigureHandlers(registry, enabled)
}

func initMetricsServer(address string, enableOpenMetrics bool, errChan chan error) {
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

}

func initEndpointDeletionHandler() {
	endpointDeletionHandler = &CiliumEndpointDeletionHandler{
		gracefulPeriod: time.Minute,
		queue:          workqueue.NewDelayingQueue(),
	}

	go func() {
		for {
			endpoint, quit := endpointDeletionHandler.queue.Get()
			if quit {
				return
			}
			enabledMetrics.ProcessCiliumEndpointDeletion(endpoint.(*types.CiliumEndpoint))
			endpointDeletionHandler.queue.Done(endpoint)
		}
	}()
}

// initMetrics initializes the metrics system
func initMetrics(address string, enabled api.Map, grpcMetrics *grpc_prometheus.ServerMetrics, enableOpenMetrics bool) (<-chan error, error) {
	e, err := initMetricHandlers(enabled)
	if err != nil {
		return nil, err
	}
	enabledMetrics = e

	registry.MustRegister(grpcMetrics)
	registry.MustRegister(LostEvents)

	errChan := make(chan error, 1)

	initMetricsServer(address, enableOpenMetrics, errChan)
	initEndpointDeletionHandler()

	return errChan, nil
}

// EnableMetrics starts the metrics server with a given list of metrics. This is the
// function Cilium uses to configure Hubble metrics in embedded mode.
func EnableMetrics(log logrus.FieldLogger, metricsServer string, m []string, grpcMetrics *grpc_prometheus.ServerMetrics, enableOpenMetrics bool) error {
	errChan, err := initMetrics(metricsServer, api.ParseMetricList(m), grpcMetrics, enableOpenMetrics)
	if err != nil {
		return fmt.Errorf("unable to setup metrics: %w", err)
	}
	go func() {
		err := <-errChan
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Error("Unable to initialize metrics server")
		}
	}()
	return nil
}

// Register registers additional metrics collectors within hubble metrics registry.
func Register(cs ...prometheus.Collector) {
	registry.MustRegister(cs...)
}
