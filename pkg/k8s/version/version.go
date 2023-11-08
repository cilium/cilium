// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package version keeps track of the Kubernetes version the client is
// connected to
package version

import (
	"context"
	"fmt"

	"github.com/blang/semver/v4"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s")

// ServerCapabilities is a list of server capabilities derived based on
// version, the Kubernetes discovery API, or probing of individual API
// endpoints.
type ServerCapabilities struct {
	// MinimalVersionMet is true when the minimal version of Kubernetes
	// required to run Cilium has been met
	MinimalVersionMet bool

	// EndpointSlice is the ability of k8s server to support endpoint slices
	EndpointSlice bool

	// EndpointSliceV1 is the ability of k8s server to support endpoint slices
	// v1. This version was introduced in K8s v1.21.0.
	EndpointSliceV1 bool
}

type cachedVersion struct {
	mutex        lock.RWMutex
	capabilities ServerCapabilities
	version      semver.Version
}

const (
	// MinimalVersionConstraint is the minimal version that Cilium supports to
	// run kubernetes.
	MinimalVersionConstraint = "1.16.0"
)

var (
	cached = cachedVersion{}

	discoveryAPIGroupV1beta1 = "discovery.k8s.io/v1beta1"
	discoveryAPIGroupV1      = "discovery.k8s.io/v1"
	endpointSliceKind        = "EndpointSlice"

	// Constraint to check support for discovery/v1 types. Support for v1
	// discovery was introduced in K8s version 1.21.
	isGEThanAPIDiscoveryV1 = versioncheck.MustCompile(">=1.21.0")

	// Constraint to check support for discovery/v1beta1 types. Support for
	// v1beta1 discovery was introduced in K8s version 1.17.
	isGEThanAPIDiscoveryV1Beta1 = versioncheck.MustCompile(">=1.17.0")

	// isGEThanMinimalVersionConstraint is the minimal version required to run
	// Cilium
	isGEThanMinimalVersionConstraint = versioncheck.MustCompile(">=" + MinimalVersionConstraint)
)

// Version returns the version of the Kubernetes apiserver
func Version() semver.Version {
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

func updateVersion(version semver.Version) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.version = version

	cached.capabilities.MinimalVersionMet = isGEThanMinimalVersionConstraint(version)
	cached.capabilities.EndpointSliceV1 = isGEThanAPIDiscoveryV1(version)
	cached.capabilities.EndpointSlice = isGEThanAPIDiscoveryV1Beta1(version)
}

func updateServerGroupsAndResources(apiResourceLists []*metav1.APIResourceList) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.capabilities.EndpointSlice = false
	cached.capabilities.EndpointSliceV1 = false
	for _, rscList := range apiResourceLists {
		if rscList.GroupVersion == discoveryAPIGroupV1beta1 {
			for _, rsc := range rscList.APIResources {
				if rsc.Kind == endpointSliceKind {
					cached.capabilities.EndpointSlice = true
					break
				}
			}
		}
		if rscList.GroupVersion == discoveryAPIGroupV1 {
			for _, rsc := range rscList.APIResources {
				if rsc.Kind == endpointSliceKind {
					cached.capabilities.EndpointSlice = true
					cached.capabilities.EndpointSliceV1 = true
					break
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

func endpointSlicesFallbackDiscovery(client kubernetes.Interface) error {
	// If a k8s version with discovery v1 is used, then do not even bother
	// checking for v1beta1
	cached.mutex.Lock()
	if cached.capabilities.EndpointSliceV1 {
		cached.capabilities.EndpointSlice = true
		cached.mutex.Unlock()
		return nil
	}
	cached.mutex.Unlock()

	// Discovery of API groups requires the API services of the apiserver to be
	// healthy. Such API services can depend on the readiness of regular pods
	// which require Cilium to function correctly. By treating failure to
	// discover API groups as fatal, a critial loop can be entered in which
	// Cilium cannot start because the API groups can't be discovered.
	//
	// Here we acknowledge the lack of discovery ability as non Fatal and fall back to probing
	// the API directly.
	_, err := client.DiscoveryV1beta1().EndpointSlices("default").Get(context.TODO(), "kubernetes", metav1.GetOptions{})
	if err == nil {
		cached.mutex.Lock()
		cached.capabilities.EndpointSlice = true
		cached.mutex.Unlock()
		return nil
	}

	if errors.IsNotFound(err) {
		log.WithError(err).Info("Unable to retrieve EndpointSlices for default/kubernetes. Disabling EndpointSlices")
		// StatusNotFound is a safe error, EndpointSlices are
		// disabled and the agent can continue.
		return nil
	}

	// Unknown error, we can't derive whether to enable or disable
	// EndpointSlices and need to error out.
	return fmt.Errorf("unable to validate EndpointSlices support: %s", err)
}

func updateK8sServerVersion(client kubernetes.Interface) error {
	var ver semver.Version

	sv, err := client.Discovery().ServerVersion()
	if err != nil {
		return err
	}

	// Try GitVersion first. In case of error fallback to MajorMinor
	if sv.GitVersion != "" {
		// This is a string like "v1.9.0"
		ver, err = versioncheck.Version(sv.GitVersion)
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	if sv.Major != "" && sv.Minor != "" {
		ver, err = versioncheck.Version(fmt.Sprintf("%s.%s", sv.Major, sv.Minor))
		if err == nil {
			updateVersion(ver)
			return nil
		}
	}

	return fmt.Errorf("cannot parse k8s server version from %+v: %s", sv, err)
}

// Update retrieves the version of the Kubernetes apiserver and derives the
// capabilities. This function must be called after connectivity to the
// apiserver has been established.
//
// Discovery of capabilities only works if the discovery API of the apiserver
// is functional. If it is not available, a warning is logged and the discovery
// falls back to probing individual API endpoints.
func Update(client kubernetes.Interface, apiDiscoveryEnabled bool) error {
	err := updateK8sServerVersion(client)
	if err != nil {
		return fmt.Errorf("failed to update Kubernetes server version: %w", err)
	}

	if !apiDiscoveryEnabled {
		if err := endpointSlicesFallbackDiscovery(client); err != nil {
			return fmt.Errorf("failed to fallback-discover endpoint slices: %w", err)
		}
		return nil
	}

	// Discovery of API groups requires the API services of the
	// apiserver to be healthy. Such API services can depend on the
	// readiness of regular pods which require Cilium to function
	// correctly. By treating failure to discover API groups as
	// fatal, a critical loop can be entered in which Cilium cannot
	// start because the API groups can't be discovered and the API
	// groups will only become discoverable once Cilium is up.
	_, apiResourceLists, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		// It doesn't make sense to retry the retrieval of this
		// information at a later point because the capabilities are
		// primarily used while the agent is starting up. Instead, fall
		// back to probing API endpoints directly.
		log.WithError(err).Warning("Unable to discover API groups and resources")
		if err := endpointSlicesFallbackDiscovery(client); err != nil {
			return fmt.Errorf("failed to fallback-discover endpoint slices after API groups discovery failure: %w", err)
		}
		return nil
	}

	updateServerGroupsAndResources(apiResourceLists)
	return nil
}
