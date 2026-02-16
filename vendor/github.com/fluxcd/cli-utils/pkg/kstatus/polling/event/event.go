// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"fmt"

	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Type is the type that describes the type of an Event that is passed back to the caller
// as resources in the cluster are being polled.
//
//go:generate stringer -type=Type -linecomment
type Type int

const (
	// ResourceUpdateEvent describes events related to a change in the status of one of the polled resources.
	ResourceUpdateEvent Type = iota // Update
	// ErrorEvent signals that the engine has encountered an error that it can not recover from. The engine
	// is shutting down and the event channel will be closed after this event.
	ErrorEvent // Error
	// SyncEvent signals that the engine has completed its initial
	// synchronization, and the cache is primed. After this point, it's safe to
	// assume that you won't miss events caused by your own subsequent actions.
	SyncEvent // Sync
)

// Event defines that type that is passed back through the event channel to notify the caller of changes
// as resources are being polled.
type Event struct {
	// Type defines the type of event.
	Type Type

	// Resource is only available for ResourceUpdateEvents. It includes information about the resource,
	// including the resource status, any errors and the resource itself (as an unstructured).
	Resource *ResourceStatus

	// Error is only available for ErrorEvents. It contains the error that caused the engine to
	// give up.
	Error error
}

// String returns a string suitable for logging
func (e Event) String() string {
	if e.Error != nil {
		return fmt.Sprintf("Event{ Type: %q, Resource: %v, Error: %q }",
			e.Type, e.Resource, e.Error)
	}
	return fmt.Sprintf("Event{ Type: %q, Resource: %v }",
		e.Type, e.Resource)
}

// ResourceStatus contains information about a resource after we have
// fetched it from the cluster and computed status.
type ResourceStatus struct {
	// Identifier contains the information necessary to locate the
	// resource within a cluster.
	Identifier object.ObjMetadata

	// Status is the computed status for this resource.
	Status status.Status

	// Resource contains the actual manifest for the resource that
	// was fetched from the cluster and used to compute status.
	Resource *unstructured.Unstructured

	// Errors contains the error if something went wrong during the
	// process of fetching the resource and computing the status.
	Error error

	// Message is text describing the status of the resource.
	Message string

	// GeneratedResources is a slice of ResourceStatus that
	// contains information and status for any generated resources
	// of the current resource.
	GeneratedResources ResourceStatuses
}

// String returns a string suitable for logging
func (rs ResourceStatus) String() string {
	if rs.Error != nil {
		return fmt.Sprintf("ResourceStatus{ Identifier: %q, Status: %q, Message: %q, Resource: %v, GeneratedResources: %v, Error: %q }",
			rs.Identifier, rs.Status, rs.Message, rs.Resource, rs.GeneratedResources, rs.Error)
	}
	return fmt.Sprintf("ResourceStatus{ Identifier: %q, Status: %q, Message: %q, Resource: %v, GeneratedResources: %v }",
		rs.Identifier, rs.Status, rs.Message, rs.Resource, rs.GeneratedResources)
}

type ResourceStatuses []*ResourceStatus

func (g ResourceStatuses) Len() int {
	return len(g)
}

func (g ResourceStatuses) Less(i, j int) bool {
	idI := g[i].Identifier
	idJ := g[j].Identifier

	if idI.Namespace != idJ.Namespace {
		return idI.Namespace < idJ.Namespace
	}
	if idI.GroupKind.Group != idJ.GroupKind.Group {
		return idI.GroupKind.Group < idJ.GroupKind.Group
	}
	if idI.GroupKind.Kind != idJ.GroupKind.Kind {
		return idI.GroupKind.Kind < idJ.GroupKind.Kind
	}
	return idI.Name < idJ.Name
}

func (g ResourceStatuses) Swap(i, j int) {
	g[i], g[j] = g[j], g[i]
}

// ResourceStatusEqual checks if two instances of ResourceStatus are the same.
// This is used to determine whether status has changed for a particular resource.
// Important to note that this does not check all fields, but only the ones
// that are considered part of the status for a resource. So if the status
// or the message of an ResourceStatus (or any of its generated ResourceStatuses)
// have changed, this will return true. Changes to the state of the resource
// itself that doesn't impact status are not considered.
func ResourceStatusEqual(or1, or2 *ResourceStatus) bool {
	if or1.Identifier != or2.Identifier ||
		or1.Status != or2.Status ||
		or1.Message != or2.Message {
		return false
	}

	// Check if generation has changed to make sure that even if
	// an update to a resource doesn't affect the status, a status event
	// will still be sent.
	if getGeneration(or1) != getGeneration(or2) {
		return false
	}

	if or1.Error != nil && or2.Error != nil && or1.Error.Error() != or2.Error.Error() {
		return false
	}
	if (or1.Error == nil && or2.Error != nil) || (or1.Error != nil && or2.Error == nil) {
		return false
	}

	if len(or1.GeneratedResources) != len(or2.GeneratedResources) {
		return false
	}

	for i := range or1.GeneratedResources {
		if !ResourceStatusEqual(or1.GeneratedResources[i], or2.GeneratedResources[i]) {
			return false
		}
	}
	return true
}

func getGeneration(r *ResourceStatus) int64 {
	if r.Resource == nil {
		return 0
	}
	return r.Resource.GetGeneration()
}
