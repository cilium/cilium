// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

package defaults

import (
	daemon "github.com/cilium/cilium/pkg/defaults"
)

const (
	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = daemon.RuntimePath + "/health.sock"

	// SockPathEnv is the environment variable to overwrite SockPath
	SockPathEnv = "CILIUM_HEALTH_SOCK"

	// HTTPPathPort is used for probing base HTTP path connectivity
	HTTPPathPort = 4240

	// L7PathPort is used for probing L7 path connectivity
	L7PathPort = 4241

	// ServicePathPort is used for probing service redirect path connectivity
	ServicePathPort = 4242

	// ServiceL7PathPort is used for probing service redirect path connectivity with L7
	ServiceL7PathPort = 4243
)
