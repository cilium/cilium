// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"net/url"
	"strings"

	k8s_metrics "k8s.io/client-go/tools/metrics"
	"k8s.io/client-go/util/workqueue"

	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

func init() {
	// The client-go Register function can be called only once,
	// but there's a possibility that another package calls it and
	// registers the client-go metrics on its own registry.
	// The metrics of one who called the init first will take effect,
	// and which one wins depends on the order of package initialization.
	// Currently, controller-runtime also calls it in its init function
	// because there's an indirect dependency on controller-runtime.
	// Given the possibility that controller-runtime wins, we should set
	// the adapters directly to override the metrics registration of
	// controller-runtime as well as calling Register function.
	// Without calling Register function here, controller-runtime will have
	// a chance to override our metrics registration.
	registerOps := k8s_metrics.RegisterOpts{
		ClientCertExpiry:      nil,
		ClientCertRotationAge: nil,
		RequestLatency:        &requestLatencyAdapter{},
		RateLimiterLatency:    &rateLimiterLatencyAdapter{},
		RequestResult:         &resultAdapter{},
	}
	k8s_metrics.Register(registerOps)
	k8s_metrics.RequestLatency = registerOps.RequestLatency
	k8s_metrics.RateLimiterLatency = registerOps.RateLimiterLatency
	k8s_metrics.RequestResult = registerOps.RequestResult
}

type workqueueMetricsProvider struct{}

func (workqueueMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	return metrics.WorkQueueDepth.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	return metrics.WorkQueueAddsTotal.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	return metrics.WorkQueueLatency.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	return metrics.WorkQueueDuration.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return metrics.WorkQueueUnfinishedWork.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return metrics.WorkQueueLongestRunningProcessor.WithLabelValues(name)
}

func (workqueueMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	return metrics.WorkQueueRetries.WithLabelValues(name)
}

// requestLatencyAdapter implements the LatencyMetric interface from k8s client-go package
type requestLatencyAdapter struct{}

func (*requestLatencyAdapter) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	metrics.KubernetesAPIInteractions.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
}

// rateLimiterLatencyAdapter implements the LatencyMetric interface from k8s client-go package
type rateLimiterLatencyAdapter struct{}

func (c *rateLimiterLatencyAdapter) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	metrics.KubernetesAPIRateLimiterLatency.WithLabelValues().Observe(latency.Seconds())
}

// resultAdapter implements the ResultMetric interface from k8s client-go package
type resultAdapter struct{}

func (r *resultAdapter) Increment(_ context.Context, code, method, host string) {
	metrics.KubernetesAPICallsTotal.WithLabelValues(host, method, code).Inc()
	// The 'code' is set to '<error>' in case an error is returned from k8s
	// more info:
	// https://github.com/kubernetes/client-go/blob/v0.18.0-rc.1/rest/request.go#L700-L703
	if code != "<error>" {
		// Consider success only if status code is 2xx
		if strings.HasPrefix(code, "2") {
			k8smetrics.LastSuccessInteraction.Reset()
		}
	}
	k8smetrics.LastInteraction.Reset()
}
