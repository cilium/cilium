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

// Package version keeps track of the Kubernetes version the client is
// connected to
package version

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"

	go_version "github.com/blang/semver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// EndpointSlice is the ability of k8s server to support endpoint slices
	EndpointSlice bool

	// FieldTypeInCRDSchema is set to true if Kubernetes supports having
	// the field Type set in the CRD Schema.
	FieldTypeInCRDSchema bool
}

type cachedVersion struct {
	mutex        lock.RWMutex
	capabilities ServerCapabilities
	version      go_version.Version
}

const (
	// MinimalVersionConstraint is the minimal version that Cilium supports to
	// run kubernetes.
	MinimalVersionConstraint = "1.11.0"
)

var (
	cached = cachedVersion{}

	discoveryAPIGroup = "discovery.k8s.io/v1beta1"
	endpointSliceKind = "EndpointSlice"

	isGEThanPatchConstraint        = versioncheck.MustCompile(">=1.13.0")
	isGEThanUpdateStatusConstraint = versioncheck.MustCompile(">=1.11.0")
	isGThanRootTypeConstraint      = versioncheck.MustCompile(">=1.12.0")

	// isGEThanMinimalVersionConstraint is the minimal version required to run
	// Cilium
	isGEThanMinimalVersionConstraint = versioncheck.MustCompile(">=" + MinimalVersionConstraint)
)

// Version returns the version of the Kubernetes apiserver
func Version() go_version.Version {
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

func updateVersion(version go_version.Version) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.version = version

	cached.capabilities.Patch = option.Config.K8sForceJSONPatch || isGEThanPatchConstraint(version)
	cached.capabilities.UpdateStatus = isGEThanUpdateStatusConstraint(version)
	cached.capabilities.MinimalVersionMet = isGEThanMinimalVersionConstraint(version)
	cached.capabilities.FieldTypeInCRDSchema = isGThanRootTypeConstraint(version)
}

func updateServerGroupsAndResources(apiGroups []*metav1.APIGroup, apiResourceLists []*metav1.APIResourceList) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.capabilities.EndpointSlice = false
	for _, rscList := range apiResourceLists {
		if rscList.GroupVersion == discoveryAPIGroup {
			for _, rsc := range rscList.APIResources {
				if rsc.Kind == endpointSliceKind {
					cached.capabilities.EndpointSlice = true
				}
			}
		}
	}
}

// Force forces the use of a specific version
func Force(version string) error {
	ver, err := versioncheck.Version(version)
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

	apiGroups, apiResourceLists, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		return err
	}

	updateServerGroupsAndResources(apiGroups, apiResourceLists)

	// Try GitVersion first. In case of error fallback to MajorMinor
	if sv.GitVersion != "" {
		// This is a string like "v1.9.0"
		ver, err := versioncheck.Version(sv.GitVersion)
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	if sv.Major != "" && sv.Minor != "" {
		ver, err := versioncheck.Version(fmt.Sprintf("%s.%s", sv.Major, sv.Minor))
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
