// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"
	"log/slog"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type EndpointManagerConfig struct {
	// EndpointGCInterval is interval to attempt garbage collection of
	// endpoints that are no longer alive and healthy.
	EndpointGCInterval time.Duration

	// EndpointRegenInterval is interval between periodic endpoint regenerations.
	EndpointRegenInterval time.Duration

	// BPFPolicyMapPressureMetricsThreshold is minimum rate for triggering policy map pressure metrics
	BPFPolicyMapPressureMetricsThreshold float64
}

// Validate validates the EndpointManagerConfig and applies defaults for invalid values
func (c *EndpointManagerConfig) Validate(logger *slog.Logger) {
	if c.BPFPolicyMapPressureMetricsThreshold < 0 {
		c.BPFPolicyMapPressureMetricsThreshold = defaultEndpointManagerConfig.BPFPolicyMapPressureMetricsThreshold
		logger.Warn(
			fmt.Sprintf(
				"BPF policy map pressure metrics threshold must be >= 0, using default value of %f",
				c.BPFPolicyMapPressureMetricsThreshold,
			),
		)
	}
}

func (def EndpointManagerConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration(option.EndpointGCInterval, def.EndpointGCInterval,
		"Periodically monitor local endpoint health via link status on this interval and garbage collect them if they become unhealthy, set to 0 to disable")
	flags.MarkHidden(option.EndpointGCInterval)

	flags.Duration(option.EndpointRegenInterval, def.EndpointRegenInterval,
		"Periodically recalculate and re-apply endpoint configuration. Set to 0 to disable")

	flags.Float64("bpf-policy-map-pressure-metrics-threshold", def.BPFPolicyMapPressureMetricsThreshold,
		"Sets threshold for emitting pressure metrics of policy maps")
}

var defaultEndpointManagerConfig = EndpointManagerConfig{
	EndpointGCInterval:                   5 * time.Minute,
	EndpointRegenInterval:                2 * time.Minute,
	BPFPolicyMapPressureMetricsThreshold: 0.1,
}
