// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/rate"
)

const (
	apiRequestEndpointCreate = "endpoint-create"
	apiRequestEndpointDelete = "endpoint-delete"
	apiRequestEndpointGet    = "endpoint-get"
	apiRequestEndpointPatch  = "endpoint-patch"
	apiRequestEndpointList   = "endpoint-list"
)

var apiRateLimitDefaults = map[string]rate.APILimiterParameters{
	// PUT /endpoint/{id}
	apiRequestEndpointCreate: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Second * 2,
		RateLimit:                   0.5,
		RateBurst:                   4,
		ParallelRequests:            4,
		SkipInitial:                 4,
		MaxWaitDuration:             15 * time.Second,
		Log:                         false,
	},
	// DELETE /endpoint/{id}
	//
	// No maximum wait time is enforced as delete calls should always
	// succeed. Permit a large number of parallel requests to minimize
	// latency of delete calls, if the system performance allows for it,
	// the maximum number of parallel requests will grow to a larger number
	// but it will never shrink below 4. Logging is enabled for visibility
	// as frequency should be low.
	apiRequestEndpointDelete: {
		EstimatedProcessingDuration: 200 * time.Millisecond,
		AutoAdjust:                  true,
		ParallelRequests:            4,
		MinParallelRequests:         4,
		Log:                         false,
	},
	// GET /endpoint/{id}/healthz
	// GET /endpoint/{id}/log
	// GET /endpoint/{id}/labels
	// GET /endpoint/{id}/config
	//
	// All GET calls to endpoint attributes are grouped together and rate
	// limited.
	apiRequestEndpointGet: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Millisecond * 200,
		RateLimit:                   4.0,
		RateBurst:                   4,
		ParallelRequests:            4,
		MinParallelRequests:         2,
		SkipInitial:                 4,
		MaxWaitDuration:             10 * time.Second,
	},
	// PATCH /endpoint/{id}
	// PATCH /endpoint/{id}/config
	// PATCH /endpoint/{id}/labels
	//
	// These calls are similar PUT /endpoint/{id} but put into a separate
	// group as they are less likely to be expensive. They can be expensive
	// though if datapath regenerations are required. Logging is enabled
	// for visibility.
	apiRequestEndpointPatch: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Second,
		RateLimit:                   0.5,
		RateBurst:                   4,
		ParallelRequests:            4,
		SkipInitial:                 4,
		MaxWaitDuration:             15 * time.Second,
		Log:                         false,
	},
	// GET /endpoint
	//
	// Listing endpoints should be relatively quick, even with a large
	// number of endpoints on a node. Always permit two parallel requests
	// and rely on rate limiting to throttle if load becomes high.
	apiRequestEndpointList: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Millisecond * 300,
		RateLimit:                   1.0,
		RateBurst:                   4,
		ParallelRequests:            2,
		MinParallelRequests:         2,
	},
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
