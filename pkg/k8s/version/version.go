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
	"context"
	"fmt"

	k8sconfig "github.com/cilium/cilium/pkg/k8s/config"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/blang/semver/v4"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

	// WatchPartialObjectMetadata is set to true when the K8s server supports a
	// watch operation on the metav1.PartialObjectMetadata (and metav1.Table)
	// resource.
	//
	// This capability was introduced in K8s version 1.15, prior to which
	// watches cannot be performed on the aforementioned resources.
	//
	// Source:
	//   - KEP:
	//   https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/20190322-server-side-get-to-ga.md#goals
	//   - PR: https://github.com/kubernetes/kubernetes/pull/71548
	WatchPartialObjectMetadata bool
}

type cachedVersion struct {
	mutex        lock.RWMutex
	capabilities ServerCapabilities
	version      semver.Version
}

const (
	// MinimalVersionConstraint is the minimal version that Cilium supports to
	// run kubernetes.
	MinimalVersionConstraint = "1.13.0"
)

var (
	cached = cachedVersion{}

	discoveryAPIGroup      = "discovery.k8s.io/v1beta1"
	coordinationV1APIGroup = "coordination.k8s.io/v1"
	endpointSliceKind      = "EndpointSlice"
	leaseKind              = "Lease"

	// Constraint to check support for Lease type from coordination.k8s.io/v1.
	// Support for Lease resource was introduced in K8s version 1.14.
	isGEThanLeaseSupportConstraint = versioncheck.MustCompile(">=1.14.0")

	// Constraint to check support for apiextensions/v1 CRD types. Support for
	// v1 CRDs was introduced in K8s version 1.16.
	isGEThanAPIExtensionsV1CRD = versioncheck.MustCompile(">=1.16.0")

	// Constraint to check support for watching metav1.PartialObjectMetadata
	// and metav1.Table types. Support was introduced in K8s 1.15.
	isGEThanWatchPartialObjectMeta = versioncheck.MustCompile(">=1.15.0")

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
	cached.capabilities.APIExtensionsV1CRD = isGEThanAPIExtensionsV1CRD(version)
	cached.capabilities.WatchPartialObjectMetadata = isGEThanWatchPartialObjectMeta(version)
}

func updateServerGroupsAndResources(apiResourceLists []*metav1.APIResourceList) {
	cached.mutex.Lock()
	defer cached.mutex.Unlock()

	cached.capabilities.EndpointSlice = false
	cached.capabilities.LeasesResourceLock = false
	for _, rscList := range apiResourceLists {
		if rscList.GroupVersion == discoveryAPIGroup {
			for _, rsc := range rscList.APIResources {
				if rsc.Kind == endpointSliceKind {
					cached.capabilities.EndpointSlice = true
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

func leasesFallbackDiscovery(client kubernetes.Interface, conf k8sconfig.Configuration) error {
	// K8sEnableLeasesFallbackDiscovery is used to fallback leases discovery to directly
	// probing the API when we cannot discover API groups.
	// We require to check for Leases capabilities in operator only, which uses Leases
	// for leader election purposes in HA mode.
	if !conf.K8sLeasesFallbackDiscoveryEnabled() {
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
func Update(client kubernetes.Interface, conf k8sconfig.Configuration) error {
	err := updateK8sServerVersion(client)
	if err != nil {
		return err
	}

	if conf.K8sAPIDiscoveryEnabled() {
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

			return leasesFallbackDiscovery(client, conf)
		}

		updateServerGroupsAndResources(apiResourceLists)
	} else {
		if err := endpointSlicesFallbackDiscovery(client); err != nil {
			return err
		}

		return leasesFallbackDiscovery(client, conf)
	}

	return nil
}
