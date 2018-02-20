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

package xds

import (
	"context"

	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/golang/protobuf/proto"
)

// ResourceSource provides read access to a versioned set of resources.
// A single version is associated to all the contained resources.
// The version is monotonically increased for any change to the set.
type ResourceSource interface {
	// GetResources returns the current version of the resources with the given
	// names.
	// If lastVersion is not nil and the resources with the given names haven't
	// changed since lastVersion, nil is returned.
	// If resourceNames is empty, all resources are returned.
	// Should not be blocking.
	GetResources(ctx context.Context, typeURL string, lastVersion *uint64,
		node *envoy_api_v2_core.Node, resourceNames []string) (*VersionedResources, error)
}

// VersionedResources is a set of protobuf-encoded resources along with their
// version.
type VersionedResources struct {
	// Version is the version of the resources.
	Version uint64

	// ResourceNames is the list of names of resources.
	// May be empty.
	ResourceNames []string

	// Resources is the list of protobuf-encoded resources.
	// May be empty. Must be of the same length as ResourceNames.
	Resources []proto.Message

	// Canary indicates whether the client should only do a dry run of
	// using  the resources.
	Canary bool
}

// ResourceMutator provides write access to a versioned set of resources.
// A single version is associated to all the contained resources.
// The version is monotonically increased for any change to the set.
type ResourceMutator interface {
	// Upsert inserts or updates a resource from this set by name.
	// If force is true and/or the set is actually modified (resource is
	// actually inserted or updated), the set's version number is incremented
	// atomically and the returned updated value is true.
	// Otherwise, the version number is not modified and the returned updated
	// value is false.
	// The returned version value is the set's version after update.
	Upsert(typeURL string, resourceName string, resource proto.Message, force bool) (version uint64, updated bool)

	// Delete deletes a resource from this set by name.
	// If force is true and/or the set is actually modified (resource is
	// actually deleted), the set's version number is incremented
	// atomically and the returned updated value is true.
	// Otherwise, the version number is not modified and the returned updated
	// value is false.
	// The returned version value is the set's version after update.
	Delete(typeURL string, resourceName string, force bool) (version uint64, updated bool)
}

// ResourceSet provides read-write access to a versioned set of resources.
// A single version is associated to all the contained resources.
// The version is monotonically increased for any change to the set.
type ResourceSet interface {
	ResourceSource
	ResourceMutator
}

// ObservableResourceSource is a ResourceSource that allows registering observers of
// new resource versions from this source.
type ObservableResourceSource interface {
	ResourceSource

	// AddResourceVersionObserver registers an observer of new versions of
	// resources from this source.
	AddResourceVersionObserver(listener ResourceVersionObserver)

	// RemoveResourceVersionObserver unregisters an observer of new versions of
	// resources from this source.
	RemoveResourceVersionObserver(listener ResourceVersionObserver)
}

// ObservableResourceSet is a ResourceSet that allows registering observers of
// new resource versions from this source.
type ObservableResourceSet interface {
	ObservableResourceSource
	ResourceMutator
}

// ResourceVersionObserver defines the HandleNewResourceVersion method which is
// called whenever the version of the resources of a given type has changed.
type ResourceVersionObserver interface {
	// HandleNewResourceVersion notifies of a new version of the resources of
	// the given type.
	HandleNewResourceVersion(typeURL string, version uint64)
}

// BaseObservableResourceSource implements the AddResourceVersionObserver and
// RemoveResourceVersionObserver methods to handle the notification of new
// resource versions. This is meant to be used as a base to implement
// ObservableResourceSource.
type BaseObservableResourceSource struct {
	// locker is the locker used to synchronize all accesses to this source.
	locker lock.RWMutex

	// observers is the set of registered observers.
	observers map[ResourceVersionObserver]struct{}
}

// NewBaseObservableResourceSource initializes the given set.
func NewBaseObservableResourceSource() *BaseObservableResourceSource {
	return &BaseObservableResourceSource{
		observers: make(map[ResourceVersionObserver]struct{}),
	}
}

// AddResourceVersionObserver registers an observer to be notified of new
// resource version.
func (s *BaseObservableResourceSource) AddResourceVersionObserver(observer ResourceVersionObserver) {
	s.locker.Lock()
	defer s.locker.Unlock()

	s.observers[observer] = struct{}{}
}

// RemoveResourceVersionObserver unregisters an observer that was previously
// registered by calling AddResourceVersionObserver.
func (s *BaseObservableResourceSource) RemoveResourceVersionObserver(observer ResourceVersionObserver) {
	s.locker.Lock()
	defer s.locker.Unlock()

	delete(s.observers, observer)
}

// NotifyNewResourceVersionRLocked notifies registered observers that a new version of
// the resources of the given type is available.
// This function MUST be called with locker's lock acquired.
func (s *BaseObservableResourceSource) NotifyNewResourceVersionRLocked(typeURL string, version uint64) {
	for o := range s.observers {
		o.HandleNewResourceVersion(typeURL, version)
	}
}
