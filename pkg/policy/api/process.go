// Copyright 2018 Authors of Cilium
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

package api

type ProcessContextSelector struct {
	// K8sContainerName is the name associated with the container in the
	// PodSpec. This does *not* correlate with the docker runtime container
	// runtime.
	//
	// +optional
	K8sContainerName string

	// Command defines the command the process is executing.
	//
	// +optional
	Command string

	// CommandLineRegexp is a regular expression that must match the full
	// command line being executed.
	//
	// +optional
	CommandLineRegexp string

	// ContainerPID is the process ID in the container process namespace.
	//
	// Example:
	// Only allow PID 1 in the container to match the process context
	//
	// +optional
	ContainerPID int
}
