// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	"github.com/spf13/pflag"
)

type leaderElectionConfig struct {
	LeaseDuration       time.Duration `mapstructure:"leader-election-lease-duration"`
	RenewDeadline       time.Duration `mapstructure:"leader-election-renew-deadline"`
	RetryPeriod         time.Duration `mapstructure:"leader-election-retry-period"`
	ResourceLockTimeout time.Duration `mapstructure:"leader-election-resource-lock-timeout"`
}

var defaultLeaderElectionConfig = leaderElectionConfig{
	LeaseDuration: 15 * time.Second,
	RenewDeadline: 10 * time.Second,
	RetryPeriod:   2 * time.Second,
}

func (cfg leaderElectionConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("leader-election-lease-duration", defaultLeaderElectionConfig.LeaseDuration,
		"Duration that non-leader candidates will wait to force acquire leadership")
	flags.Duration("leader-election-renew-deadline", defaultLeaderElectionConfig.RenewDeadline,
		"Duration that current acting master will retry refreshing leadership before giving up the lock")
	flags.Duration("leader-election-retry-period", defaultLeaderElectionConfig.RetryPeriod,
		"Duration the LeaderElector clients should wait between tries of actions")
	flags.Duration("leader-election-resource-lock-timeout", defaultLeaderElectionConfig.ResourceLockTimeout,
		"Timeout for HTTP requests to acquire/renew the leader election resource lock. When 0, defaults to max(1s, renew-deadline/2)")
}
