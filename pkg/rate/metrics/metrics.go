// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/rate"
)

func APILimiterObserver() rate.MetricsObserver {
	return &apiRateLimitingMetrics{}
}

type apiRateLimitingMetrics struct{}

func (a *apiRateLimitingMetrics) ProcessedRequest(name string, v rate.MetricsValues) {
	metrics.APILimiterProcessingDuration.WithLabelValues(name, "mean").Set(v.MeanProcessingDuration)
	metrics.APILimiterProcessingDuration.WithLabelValues(name, "estimated").Set(v.EstimatedProcessingDuration)
	metrics.APILimiterWaitDuration.WithLabelValues(name, "mean").Set(v.MeanWaitDuration)
	metrics.APILimiterWaitDuration.WithLabelValues(name, "max").Set(v.MaxWaitDuration.Seconds())
	metrics.APILimiterWaitDuration.WithLabelValues(name, "min").Set(v.MinWaitDuration.Seconds())
	metrics.APILimiterRequestsInFlight.WithLabelValues(name, "in-flight").Set(float64(v.CurrentRequestsInFlight))
	metrics.APILimiterRequestsInFlight.WithLabelValues(name, "limit").Set(float64(v.ParallelRequests))
	metrics.APILimiterRateLimit.WithLabelValues(name, "limit").Set(float64(v.Limit))
	metrics.APILimiterRateLimit.WithLabelValues(name, "burst").Set(float64(v.Burst))
	metrics.APILimiterAdjustmentFactor.WithLabelValues(name).Set(v.AdjustmentFactor)

	if v.Outcome == "" {
		metrics.APILimiterWaitHistoryDuration.WithLabelValues(name).Observe(v.WaitDuration.Seconds())
		v.Outcome = metrics.Error2Outcome(v.Error)
	}

	metrics.APILimiterProcessedRequests.WithLabelValues(name, v.Outcome).Inc()
}
