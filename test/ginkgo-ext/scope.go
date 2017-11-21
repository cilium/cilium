// Copyright 2017 Authors of Cilium
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

package ginkgoext

import (
	"fmt"
	"strings"

	"github.com/onsi/ginkgo/config"

	"github.com/cilium/cilium/test/helpers"
)

// GetScope returns the scope for the currently running test.
func GetScope() string {
	focusString := strings.ToLower(config.GinkgoConfig.FocusString)
	switch {
	case strings.HasPrefix(focusString, "run"):
		return helpers.Runtime
	case strings.HasPrefix(focusString, helpers.K8s):
		return helpers.K8s
	case strings.Contains(focusString, "nightly"):
		// Nightly tests run in a Kubernetes environment.
		return helpers.K8s
	default:
		return helpers.Runtime
	}
}

// GetScopeWithVersion returns the scope of the running test. If the scope is
// k8s, then it returns k8s scope along with the version of k8s that is running.
func GetScopeWithVersion() string {
	result := GetScope()
	if result != helpers.K8s {
		return result
	}
	return fmt.Sprintf("%s-%s", result, helpers.GetCurrentK8SEnv())
}
