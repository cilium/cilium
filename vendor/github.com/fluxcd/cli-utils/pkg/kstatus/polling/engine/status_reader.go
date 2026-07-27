// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// StatusReader is the main interface for computing status for resources. In this context,
// a status reader is an object that can fetch a resource of a specific
// GroupKind from the cluster and compute its status. For resources that
// can own generated resources, the engine might also have knowledge about
// how to identify these generated resources and how to compute status for
// these generated resources.
type StatusReader interface {
	// Supports tells the caller whether the StatusReader can compute status for
	// the provided GroupKind.
	Supports(schema.GroupKind) bool

	// ReadStatus will fetch the resource identified by the given identifier
	// from the cluster and return an ResourceStatus that will contain
	// information about the latest state of the resource, its computed status
	// and information about any generated resources. Errors would usually be
	// added to the event.ResourceStatus, but in the case of fatal errors
	// that aren't connected to the particular resource, an error can also
	// be returned. Currently, only context cancellation and deadline exceeded
	// will cause an error to be returned.
	ReadStatus(ctx context.Context, reader ClusterReader, resource object.ObjMetadata) (*event.ResourceStatus, error)

	// ReadStatusForObject is similar to ReadStatus, but instead of looking up the
	// resource based on an identifier, it will use the passed-in resource.
	// Errors would usually be added to the event.ResourceStatus, but in the case
	// of fatal errors that aren't connected to the particular resource, an error
	// can also be returned. Currently, only context cancellation and deadline exceeded
	// will cause an error to be returned.
	ReadStatusForObject(ctx context.Context, reader ClusterReader, object *unstructured.Unstructured) (*event.ResourceStatus, error)
}
