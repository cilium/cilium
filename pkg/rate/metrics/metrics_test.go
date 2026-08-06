// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/rate"
)

func TestAPILimiterMetricsDeregistration(t *testing.T) {
	metrics.NewLegacyMetrics()

	obs := APILimiterObserver()
	apiName := "test-api-call"

	obs.ProcessedRequest(apiName, rate.MetricsValues{
		Outcome:                     "success",
		ReturnCode:                  200,
		MeanProcessingDuration:      0.1,
		EstimatedProcessingDuration: 0.2,
		MeanWaitDuration:            0.05,
		MaxWaitDuration:             time.Second,
		MinWaitDuration:             time.Millisecond,
		CurrentRequestsInFlight:     2,
		ParallelRequests:            10,
		Limit:                       5.0,
		Burst:                       10,
		AdjustmentFactor:            1.0,
	})

	// Verify that the metrics are registered and exist.
	assert.True(t, metrics.APILimiterProcessingDuration.DeleteLabelValues(apiName, "mean"))
	assert.True(t, metrics.APILimiterProcessingDuration.DeleteLabelValues(apiName, "estimated"))

	// Re-emit metrics so they are registered again before calling DeRegister.
	obs.ProcessedRequest(apiName, rate.MetricsValues{
		Outcome:    "success",
		ReturnCode: 200,
	})

	// Call DeRegister on the observer for the given API call name.
	obs.DeRegister(apiName)

	// Verify all associated metrics series for the API call name were deleted.
	assert.False(t, metrics.APILimiterProcessingDuration.DeleteLabelValues(apiName, "mean"))
	assert.False(t, metrics.APILimiterProcessingDuration.DeleteLabelValues(apiName, "estimated"))
	assert.False(t, metrics.APILimiterWaitDuration.DeleteLabelValues(apiName, "mean"))
	assert.False(t, metrics.APILimiterWaitDuration.DeleteLabelValues(apiName, "max"))
	assert.False(t, metrics.APILimiterWaitDuration.DeleteLabelValues(apiName, "min"))
	assert.False(t, metrics.APILimiterRequestsInFlight.DeleteLabelValues(apiName, "in-flight"))
	assert.False(t, metrics.APILimiterRequestsInFlight.DeleteLabelValues(apiName, "limit"))
	assert.False(t, metrics.APILimiterRateLimit.DeleteLabelValues(apiName, "limit"))
	assert.False(t, metrics.APILimiterRateLimit.DeleteLabelValues(apiName, "burst"))
	assert.False(t, metrics.APILimiterAdjustmentFactor.DeleteLabelValues(apiName))
	assert.False(t, metrics.APILimiterProcessedRequests.DeleteLabelValues(apiName, "success", "200"))
}
