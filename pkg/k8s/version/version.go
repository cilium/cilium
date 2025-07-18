// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package version keeps track of the Kubernetes version the client is
// connected to
package version

import (
	"fmt"
	"log/slog"

	"github.com/blang/semver/v4"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// ServerCapabilities is a list of server capabilities derived based on
// version, the Kubernetes discovery API, or probing of individual API
// endpoints.
type ServerCapabilities struct {
	// MinimalVersionMet is true when the minimal version of Kubernetes
	// required to run Cilium has been met
	MinimalVersionMet bool
}

type cachedVersion struct {
	mutex        lock.RWMutex
	capabilities ServerCapabilities
	version      semver.Version
}

const (
	// MinimalVersionConstraint is the minimal version that Cilium supports to
	// run kubernetes.
	MinimalVersionConstraint = "1.21.0"
)

var (
	cached = cachedVersion{}

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

	return fmt.Errorf("cannot parse k8s server version from %+v: %w", sv, err)
}

// Update retrieves the version of the Kubernetes apiserver and derives the
// capabilities. This function must be called after connectivity to the
// apiserver has been established.
//
// Discovery of capabilities only works if the discovery API of the apiserver
// is functional. If it is not available, a warning is logged and the discovery
// falls back to probing individual API endpoints.
func Update(logger *slog.Logger, client kubernetes.Interface, apiDiscoveryEnabled bool) error {
	err := updateK8sServerVersion(client)
	if err != nil {
		return err
	}

	return nil
}
