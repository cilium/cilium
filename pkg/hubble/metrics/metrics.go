// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"crypto/tls"
	"net/http"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/util/workqueue"

	"github.com/sirupsen/logrus"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/crypto/certloader"
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
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/time"
)

type CiliumEndpointDeletionHandler struct {
	gracefulPeriod time.Duration
	queue          workqueue.DelayingInterface
}

var (
	enabledMetrics          *api.Handlers
	Registry                = prometheus.NewPedanticRegistry()
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

// Metrics related to Hubble metrics HTTP requests handling
var (
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "metrics_http_handler_requests_total",
		Help:      "A counter for requests to Hubble metrics handler.",
	}, []string{"code"})
	RequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "metrics_http_handler_request_duration_seconds",
		Help:      "A histogram of latencies of Hubble metrics handler.",
	}, []string{"code"})
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

// InitMetrics initializes the metrics system
func InitMetrics(reg *prometheus.Registry, enabled api.Map, grpcMetrics *grpc_prometheus.ServerMetrics) error {
	e, err := initMetricHandlers(reg, enabled)
	if err != nil {
		return err
	}
	enabledMetrics = e

	reg.MustRegister(grpcMetrics)
	reg.MustRegister(LostEvents)
	reg.MustRegister(RequestsTotal)
	reg.MustRegister(RequestDuration)

	initEndpointDeletionHandler()

	return nil
}

func initMetricHandlers(reg *prometheus.Registry, enabled api.Map) (*api.Handlers, error) {
	return api.DefaultRegistry().ConfigureHandlers(reg, enabled)
}

func InitMetricsServerHandler(srv *http.Server, reg *prometheus.Registry, enableOpenMetrics bool) {
	mux := http.NewServeMux()
	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: enableOpenMetrics,
	})
	handler = promhttp.InstrumentHandlerCounter(RequestsTotal, handler)
	handler = promhttp.InstrumentHandlerDuration(RequestDuration, handler)
	mux.Handle("/metrics", handler)

	srv.Handler = mux
}

func StartMetricsServer(srv *http.Server, log logrus.FieldLogger, metricsTLSConfig *certloader.WatchedServerConfig, grpcMetrics *grpc_prometheus.ServerMetrics) error {
	if metricsTLSConfig != nil {
		srv.TLSConfig = metricsTLSConfig.ServerConfig(&tls.Config{ //nolint:gosec
			MinVersion: serveroption.MinTLSVersion,
		})
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}
