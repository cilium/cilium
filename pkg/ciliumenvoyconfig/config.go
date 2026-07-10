// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

type CECConfig struct {
	EnvoyConfigRetryInterval time.Duration
	EnvoyConfigTimeout       time.Duration
}

func (r CECConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("envoy-config-retry-interval", 15*time.Second, "Interval in which an attempt is made to reconcile failed EnvoyConfigs. If the duration is zero, the retry is deactivated.")
	flags.Duration("envoy-config-timeout", 2*time.Minute, "Timeout that determines how long to wait for Envoy to N/ACK CiliumEnvoyConfig resources")
}
