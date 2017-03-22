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

const (
	// RuntimePath is the default path to the runtime directory
	RuntimePath = "/var/run/cilium"

	// RuntimePathRights are the default access rights of the RuntimePath directory
	RuntimePathRights = 0770

	// BpfDir is the default path for template files relative to RuntimePath
	BpfDir = "bpf"

	// LibraryPath is the default path to the cilium libraries directory
	LibraryPath = "/var/lib/cilium"

	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = "/var/run/cilium.sock"

	// SockPathEnv is the environment variable to overwrite SockPath
	SockPathEnv = "CILIUM_SOCK"
)
