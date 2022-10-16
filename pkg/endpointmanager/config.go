// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/option"
)

type EndpointManagerConfig struct {
	// EndpointGCInterval is interval to attempt garbage collection of
	// endpoints that are no longer alive and healthy.
	EndpointGCInterval time.Duration
}

func (def EndpointManagerConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration(option.EndpointGCInterval, def.EndpointGCInterval,
		"Periodically monitor local endpoint health via link status on this interval and garbage collect them if they become unhealthy, set to 0 to disable")
	flags.MarkHidden(option.EndpointGCInterval)
}

var defaultEndpointManagerConfig = EndpointManagerConfig{
	EndpointGCInterval: 5 * time.Minute,
}
