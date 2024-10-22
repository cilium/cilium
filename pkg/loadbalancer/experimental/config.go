// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type Config struct {
	EnableExperimentalLB bool          `mapstructure:"enable-experimental-lb"`
	RetryBackoffMin      time.Duration `mapstructure:"lb-retry-backoff-min"`
	RetryBackoffMax      time.Duration `mapstructure:"lb-retry-backoff-max"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-experimental-lb", def.EnableExperimentalLB, "Enable experimental load-balancing control-plane")
	flags.MarkHidden("enable-experimental-lb")

	flags.Duration("lb-retry-backoff-min", def.RetryBackoffMin, "Minimum amount of time to wait before retrying LB operation")
	flags.MarkHidden("lb-retry-backoff-min")

	flags.Duration("lb-retry-backoff-max", def.RetryBackoffMin, "Maximum amount of time to wait before retrying LB operation")
	flags.MarkHidden("lb-retry-backoff-max")
}

var DefaultConfig = Config{
	EnableExperimentalLB: false,
	RetryBackoffMin:      50 * time.Millisecond,
	RetryBackoffMax:      time.Minute,
}

// TestConfig are the configuration options for testing. Only provided by tests and not present in the agent.
type TestConfig struct {
	TestFaultProbability float32 `mapstructure:"lb-test-fault-probability"`
}

func (def TestConfig) Flags(flags *pflag.FlagSet) {
	flags.Float32("lb-test-fault-probability", def.TestFaultProbability, "Probability for fault injection in LBMaps")
	flags.MarkHidden("lb-test-fault-probability")
}

// ExternalConfig are configuration options derived from external sources such as
// DaemonConfig. This avoids direct access of larger configuration structs.
type ExternalConfig struct {
	ExternalClusterIP        bool
	EnableSessionAffinity    bool
	NodePortMin, NodePortMax uint16
}

func newExternalConfig(cfg *option.DaemonConfig) ExternalConfig {
	return ExternalConfig{
		ExternalClusterIP:     cfg.ExternalClusterIP,
		EnableSessionAffinity: cfg.EnableSessionAffinity,
		NodePortMin:           uint16(cfg.NodePortMin),
		NodePortMax:           uint16(cfg.NodePortMax),
	}
}
