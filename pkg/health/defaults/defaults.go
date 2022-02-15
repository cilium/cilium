// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	HTTPPathPort = daemon.ClusterHealthPort

	// HealthEPName is the name used for the health endpoint, which is also
	// used by the CLI client to detect when connectivity health is enabled
	HealthEPName = "cilium-health-ep"
)
