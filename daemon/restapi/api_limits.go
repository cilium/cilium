// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/rate"
	ratemetrics "github.com/cilium/cilium/pkg/rate/metrics"
	"github.com/cilium/cilium/pkg/time"
)

var rateLimiterCell = cell.Module(
	"rate-limiter",
	"Rate limiting for Cilium API requests",

	cell.Config(defaultRateLimiterConfig),
	cell.Provide(newApiRateLimiter),
)

type rateLimiterConfig struct {
	APIRateLimit string
}

func (def rateLimiterConfig) Flags(flags *pflag.FlagSet) {
	flags.String(
		"api-rate-limit",
		def.APIRateLimit,
		"API rate limiting configuration (example: --api-rate-limit endpoint-create=rate-limit:10/m,rate-burst:2)")
}

var defaultRateLimiterConfig = rateLimiterConfig{
	APIRateLimit: "",
}

func newApiRateLimiter(cfg rateLimiterConfig) (*rate.APILimiterSet, error) {
	config, err := command.ToStringMapStringE(cfg.APIRateLimit)
	if err != nil {
		return nil, err
	}
	return rate.NewAPILimiterSet(config, apiRateLimitDefaults, ratemetrics.APILimiterObserver())
}

const (
	APIRequestEndpointCreate = "endpoint-create"
	APIRequestEndpointDelete = "endpoint-delete"
	APIRequestEndpointGet    = "endpoint-get"
	APIRequestEndpointPatch  = "endpoint-patch"
	APIRequestEndpointList   = "endpoint-list"
)

var apiRateLimitDefaults = map[string]rate.APILimiterParameters{
	// PUT /endpoint/{id}
	APIRequestEndpointCreate: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Second * 2,
		RateLimit:                   0.5,
		RateBurst:                   4,
		ParallelRequests:            4,
		MinParallelRequests:         2,
		SkipInitial:                 4,
		MaxWaitDuration:             60 * time.Second, // Kubelet has a PodSandbox creation timeout of 4 minutes, in total.
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
	APIRequestEndpointDelete: {
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
	APIRequestEndpointGet: {
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
	APIRequestEndpointPatch: {
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
	APIRequestEndpointList: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Millisecond * 300,
		RateLimit:                   1.0,
		RateBurst:                   4,
		ParallelRequests:            2,
		MinParallelRequests:         2,
	},
}
