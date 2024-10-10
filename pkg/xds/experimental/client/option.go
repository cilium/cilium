// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"time"

	"github.com/cilium/cilium/pkg/envoy"

	"google.golang.org/grpc/codes"
)

type Options struct {
	RetryBackoff       BackoffParams
	BootstrapResources []string
	UseSOTW            bool `mapstructure:"xds-use-sotw-protocol"`
	RetryConnection    bool
	IsRetriable        func(code codes.Code) (retry bool)
}

type BackoffParams struct {
	Min, Max, Reset time.Duration
}

var Defaults = &Options{
	RetryBackoff: BackoffParams{
		Min:   time.Second,
		Max:   time.Minute,
		Reset: 2 * time.Minute,
	},
	// BootstrapResources should consist of subset of Listener, Clusters based on:
	// https://www.envoyproxy.io/docs/envoy/v1.31.0/api-docs/xds_protocol#client-configuration
	BootstrapResources: []string{envoy.ListenerTypeURL, envoy.ClusterTypeURL},
	IsRetriable: func(code codes.Code) bool {
		switch code {
		case codes.PermissionDenied, codes.Aborted, codes.Unauthenticated, codes.Unavailable, codes.Canceled:
			return false
		}
		return true
	},
}
