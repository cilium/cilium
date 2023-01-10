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

	// LeasesResourceLock is the ability of K8s server to support Lease type
	// from coordination.k8s.io/v1 API for leader election purposes(currently only in operator).
	// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#lease-v1-coordination-k8s-io
	//
	// This capability was introduced in K8s version 1.14, prior to which
	// we don't support HA mode for the cilium-operator.
	LeasesResourceLock bool

	// APIExtensionsV1CRD is set to true when the K8s server supports
	// apiextensions/v1 CRDs. TODO: Add link to docs
	//
	// This capability was introduced in K8s version 1.16, prior to which
	// apiextensions/v1beta1 CRDs were used exclusively.
	APIExtensionsV1CRD bool
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
	coordinationV1APIGroup   = "coordination.k8s.io/v1"
	endpointSliceKind        = "EndpointSlice"
	leaseKind                = "Lease"

	// Constraint to check support for Lease type from coordination.k8s.io/v1.
	// Support for Lease resource was introduced in K8s version 1.14.
	isGEThanLeaseSupportConstraint = versioncheck.MustCompile(">=1.14.0")

	// Constraint to check support for apiextensions/v1 CRD types. Support for
	// v1 CRDs was introduced in K8s version 1.16.
	isGEThanAPIExtensionsV1CRD = versioncheck.MustCompile(">=1.16.0")

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

func DisableLeasesResourceLock() {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()
	cached.capabilities.LeasesResourceLock = false
}

func updateVersion(version semver.Version) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.version = version

	cached.capabilities.MinimalVersionMet = isGEThanMinimalVersionConstraint(version)
	cached.capabilities.APIExtensionsV1CRD = isGEThanAPIExtensionsV1CRD(version)
	cached.capabilities.EndpointSliceV1 = isGEThanAPIDiscoveryV1(version)
	cached.capabilities.EndpointSlice = isGEThanAPIDiscoveryV1Beta1(version)
}

func updateServerGroupsAndResources(apiResourceLists []*metav1.APIResourceList) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.capabilities.EndpointSlice = false
	cached.capabilities.EndpointSliceV1 = false
	cached.capabilities.LeasesResourceLock = false
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

		if rscList.GroupVersion == coordinationV1APIGroup {
			for _, rsc := range rscList.APIResources {
				if rsc.Kind == leaseKind {
					cached.capabilities.LeasesResourceLock = true
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

func leasesFallbackDiscovery(client kubernetes.Interface, apiDiscoveryEnabled bool) error {
	// apiDiscoveryEnabled is used to fallback leases discovery to directly
	// probing the API when we cannot discover API groups.
	// We require to check for Leases capabilities in operator only, which uses Leases
	// for leader election purposes in HA mode.
	if !apiDiscoveryEnabled {
		log.Debugf("Skipping Leases support fallback discovery")
		return nil
	}

	cached.mutex.RLock()
	// Here we check if we are running a K8s version that has support for Leases.
	if !isGEThanLeaseSupportConstraint(cached.version) {
		cached.mutex.RUnlock()
		return nil
	}
	cached.mutex.RUnlock()

	// Similar to endpointSlicesFallbackDiscovery here we fallback to probing the Kubernetes
	// API directly. `kube-controller-manager` creates a lease in the kube-system namespace
	// and here we try and see if that Lease exists.
	_, err := client.CoordinationV1().Leases("kube-system").Get(context.TODO(), "kube-controller-manager", metav1.GetOptions{})
	if err == nil {
		cached.mutex.Lock()
		cached.capabilities.LeasesResourceLock = true
		cached.mutex.Unlock()
		return nil
	}

	if errors.IsNotFound(err) {
		log.WithError(err).Info("Unable to retrieve Leases for kube-controller-manager. Disabling LeasesResourceLock")
		// StatusNotFound is a safe error, Leases are
		// disabled and the agent can continue
		return nil
	}

	// Unknown error, we can't derive whether to enable or disable
	// LeasesResourceLock and need to error out
	return fmt.Errorf("unable to validate LeasesResourceLock support: %s", err)
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
		return err
	}

	if apiDiscoveryEnabled {
		// Discovery of API groups requires the API services of the
		// apiserver to be healthy. Such API services can depend on the
		// readiness of regular pods which require Cilium to function
		// correctly. By treating failure to discover API groups as
		// fatal, a critical loop can be entered in which Cilium cannot
		// start because the API groups can't be discovered and th API
		// groups will only become discoverable once Cilium is up.
		_, apiResourceLists, err := client.Discovery().ServerGroupsAndResources()
		if err != nil {
			// It doesn't make sense to retry the retrieval of this
			// information at a later point because the capabilities are
			// primiarly used while the agent is starting up. Instead, fall
			// back to probing API endpoints directly.
			log.WithError(err).Warning("Unable to discover API groups and resources")
			if err := endpointSlicesFallbackDiscovery(client); err != nil {
				return err
			}

			return leasesFallbackDiscovery(client, apiDiscoveryEnabled)
		}

		updateServerGroupsAndResources(apiResourceLists)
	} else {
		if err := endpointSlicesFallbackDiscovery(client); err != nil {
			return err
		}

		return leasesFallbackDiscovery(client, apiDiscoveryEnabled)
	}

	return nil
}
