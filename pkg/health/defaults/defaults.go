// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
