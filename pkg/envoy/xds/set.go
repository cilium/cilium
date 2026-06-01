// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/container/set"
)

// ResourceSource provides read access to a versioned set of resources.
// A single version is associated to all the contained resources.
// The version is monotonically increased for any change to the set.
type ResourceSource interface {
	// GetResources returns the current version of the resources with the given
	// names. If resourceNames is empty all are returned.
	// If lastVersion is not zero and the resources with the given names haven't
	// changed since lastVersion, nil is returned.
	// Should not be blocking.
	GetResources(typeURL string, lastVersion uint64, resourceNames []string) *VersionedResources

	// VersionState returns the current overall cache version together with a
	// channel that is closed when a strictly newer version becomes available.
	// The version and channel are sampled atomically.
	VersionState() (version uint64, changed <-chan struct{})

	// GetDeltaResources returns the delta xDS changes for the currently tracked
	// subscriptions relative to the client's last ACKed cache version.
	// Empty subscriptions and "*" both track all resources.
	// forceResponseNames forces the named resources, or all resources when it
	// contains "*", into the next response even if their version is not newer
	// than lastAckedVersion.
	GetDeltaResources(typeURL string, lastAckedVersion uint64, subscriptions set.Set[string], ackedResourceNames set.Set[string], forceResponseNames set.Set[string], forceEmptyResponse bool) *VersionedResources

	// EnsureVersion increases this resource set's version to be past the
	// given version. If the current version is already higher than that, this has no effect.
	EnsureVersion(typeURL string, version uint64)
}

// VersionedResource is a single protobuf-encoded resource along with it's version.
type VersionedResource struct {
	// Name is the name of a resource. Must not be empty for Delta xDS.
	Name string
	// Version is the version of this specific resource.
	// Zero if not-tracked.
	// Must be non-zero for Delta xDS
	Version uint64
	// Resource is the protobuf resource.
	Resource proto.Message
}

// VersionedResources is a set of protobuf-encoded resources along with their
// version.
type VersionedResources struct {
	// Version is the version of the xDS cache for these resources.
	Version uint64

	// VersionedResources is a set of versioned resources
	// May be empty.
	VersionedResources []VersionedResource

	// RemovedNames is only populated for delta protocol
	RemovedNames []string

	// Canary indicates whether the client should only do a dry run of
	// using  the resources.
	// Only used for state-of-the-world xDS
	Canary bool
}

func (r *VersionedResources) appendResource(name string, version uint64, resource proto.Message) {
	r.VersionedResources = append(r.VersionedResources,
		VersionedResource{
			Name:     name,
			Version:  version,
			Resource: resource,
		})
}

// ResourceMutatorRevertFunc is a function which reverts the effects of an update on a
// ResourceMutator.
// The returned version value is the set's version after update.
type ResourceMutatorRevertFunc func() (version uint64, updated bool)

// ResourceMutator provides write access to a versioned set of resources.
// A single version is associated to all the contained resources.
// The version is monotonically increased for any change to the set.
type ResourceMutator interface {
	// Upsert inserts or updates a resource from this set by name.
	// If the set is modified (the resource is actually inserted or updated),
	// the set's version number is incremented atomically and the returned
	// updated value is true.
	// Otherwise, the version number is not modified and the returned updated
	// value is false.
	// The returned version value is the set's version after update.
	// A call to the returned revert function reverts the effects of this
	// method call.
	Upsert(typeURL string, resourceName string, resource proto.Message) (version uint64, updated bool, revert ResourceMutatorRevertFunc)

	// Delete deletes a resource from this set by name.
	// If the set is modified (the resource is actually deleted), the set's
	// version number is incremented atomically and the returned updated value
	// is true.
	// Otherwise, the version number is not modified and the returned updated
	// value is false.
	// The returned version value is the set's version after update.
	// A call to the returned revert function reverts the effects of this
	// method call.
	Delete(typeURL string, resourceName string) (version uint64, updated bool, revert ResourceMutatorRevertFunc)

	// Clear deletes all the resources of the given type from this set.
	// If the set is modified (at least one resource is actually deleted),
	// the set's version number is incremented atomically and the returned
	// updated value is true.
	// Otherwise, the version number is not modified and the returned updated
	// value is false.
	// The returned version value is the set's version after update.
	// This method call cannot be reverted.
	Clear(typeURL string) (version uint64, updated bool)

	// Empty returns 'true' if there are any resources of the given type
	HasAny(typeURL string) bool
}

// ResourceSet provides read-write access to a versioned set of resources.
// A single version is associated to all the contained resources.
// The version is monotonically increased for any change to the set.
type ResourceSet interface {
	ResourceSource
	ResourceMutator
}
