// Copyright 2016-2019 Authors of Cilium
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

// Package version keeps track of the Kubernetes version the client is
// connected to
package version

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/hashicorp/go-version"
	"k8s.io/client-go/kubernetes"
)

// ServerCapabilities is a list of server capabilities derived based on version
type ServerCapabilities struct {
	// Patch is the ability to use PATCH to modify a resource
	Patch bool

	// UpdateStatus is the ability to update the status separately as a
	// sub-resource
	UpdateStatus bool

	// MinimalVersionMet is true when the minimal version of Kubernetes
	// required to run Cilium has been met
	MinimalVersionMet bool
}

type cachedVersion struct {
	mutex        lock.RWMutex
	capabilities ServerCapabilities
	version      *go_version.Version
}

var (
	cached = cachedVersion{}

	patchConstraint        = versioncheck.MustCompile(">= 1.13.0")
	updateStatusConstraint = versioncheck.MustCompile(">= 1.11.0")

	// MinimalVersionConstraint is the minimal version required to run
	// Cilium
	MinimalVersionConstraint = versioncheck.MustCompile(">= 1.11.0")
)

// Version returns the version of the Kubernetes apiserver
func Version() *go_version.Version {
	cached.mutex.RLock()
	c := cached.version
	cached.mutex.RUnlock()
	return c
}

// Capabilities returns the capabilities of the Kubernetes apiserver
func Capabilities() ServerCapabilities {
	cached.mutex.RLock()
	c := cached.capabilities
	cached.mutex.RUnlock()
	return c
}

func updateVersion(version *go_version.Version) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.version = version

	cached.capabilities.Patch = patchConstraint.Check(version) || option.Config.K8sForceJSONPatch
	cached.capabilities.UpdateStatus = updateStatusConstraint.Check(version)
	cached.capabilities.MinimalVersionMet = MinimalVersionConstraint.Check(version)
}

// Force forces the use of a specific version
func Force(version string) error {
	ver, err := go_version.NewVersion(version)
	if err != nil {
		return err
	}
	updateVersion(ver)
	return nil
}

// Update retrieves the version of the Kubernetes apiserver and derives the
// capabilities. This function must be called after connectivity to the
// apiserver has been established.
func Update(client kubernetes.Interface) error {
	sv, err := client.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	// Try GitVersion first. In case of error fallback to MajorMinor
	if sv.GitVersion != "" {
		// This is a string like "v1.9.0"
		ver, err := go_version.NewVersion(sv.GitVersion)
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	if sv.Major != "" && sv.Minor != "" {
		ver, err := go_version.NewVersion(fmt.Sprintf("%s.%s", sv.Major, sv.Minor))
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	if err != nil {
		return fmt.Errorf("cannot parse k8s server version from %+v: %s", sv, err)
	}
	return fmt.Errorf("cannot parse k8s server version from %+v", sv)
}
