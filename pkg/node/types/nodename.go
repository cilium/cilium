// Copyright 2016-2020 Authors of Cilium
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

package types

import (
	"os"

	k8sConsts "github.com/cilium/cilium/pkg/k8s/constants"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	nodeName = "localhost"
)

// SetName sets the name of the local node. This will overwrite the value that
// is automatically retrieved with `os.Hostname()`.
//
// Note: This function is currently designed to only be called during the
// bootstrapping procedure of the agent where no parallelism exists. If you
// want to use this function in later stages, a mutex must be added first.
func SetName(name string) {
	nodeName = name
}

// GetName returns the name of the local node. The value returned was either
// previously set with SetName(), retrieved via `os.Hostname()`, or as a last
// resort is hardcoded to "localhost".
func GetName() string {
	return nodeName
}

func init() {
	// Give priority to the environment variable available in the Cilium agent
	if name := os.Getenv(k8sConsts.EnvNodeNameSpec); name != "" {
		nodeName = name
		return
	}
	if h, err := os.Hostname(); err != nil {
		log.WithError(err).Warn("Unable to retrieve local hostname")
	} else {
		log.WithField(logfields.NodeName, h).Debug("os.Hostname() returned")
		nodeName = h
	}
}
