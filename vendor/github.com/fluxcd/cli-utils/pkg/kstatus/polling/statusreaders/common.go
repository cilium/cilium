// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package statusreaders

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/cli-utils/pkg/object"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// baseStatusReader is the implementation of the StatusReader interface defined
// in the engine package. It contains the basic logic needed for every resource.
// In order to handle resource specific logic, it must include an implementation
// of the resourceTypeStatusReader interface.
// In practice we will create many instances of baseStatusReader, each with a different
// implementation of the resourceTypeStatusReader interface and therefore each
// of the instances will be able to handle different resource types.
type baseStatusReader struct {
	// mapper provides a way to look up the resource types that are available
	// in the cluster.
	mapper meta.RESTMapper

	// resourceStatusReader is an resource-type specific implementation
	// of the resourceTypeStatusReader interface. While the baseStatusReader
	// contains the logic shared between all resource types, this implementation
	// will contain the resource specific info.
	resourceStatusReader resourceTypeStatusReader
}

// resourceTypeStatusReader is an interface that can be implemented differently
// for each resource type.
type resourceTypeStatusReader interface {
	Supports(gk schema.GroupKind) bool
	ReadStatusForObject(ctx context.Context, reader engine.ClusterReader, object *unstructured.Unstructured) (*event.ResourceStatus, error)
}

func (b *baseStatusReader) Supports(gk schema.GroupKind) bool {
	return b.resourceStatusReader.Supports(gk)
}

// ReadStatus reads the object identified by the passed-in identifier and computes it's status. It reads
// the resource here, but computing status is delegated to the ReadStatusForObject function.
func (b *baseStatusReader) ReadStatus(ctx context.Context, reader engine.ClusterReader, identifier object.ObjMetadata) (*event.ResourceStatus, error) {
	object, err := b.lookupResource(ctx, reader, identifier)
	if err != nil {
		return errIdentifierToResourceStatus(err, identifier)
	}
	return b.resourceStatusReader.ReadStatusForObject(ctx, reader, object)
}

// ReadStatusForObject computes the status for the passed-in object. Since this is specific for each
// resource type, the actual work is delegated to the implementation of the resourceTypeStatusReader interface.
func (b *baseStatusReader) ReadStatusForObject(ctx context.Context, reader engine.ClusterReader, object *unstructured.Unstructured) (*event.ResourceStatus, error) {
	return b.resourceStatusReader.ReadStatusForObject(ctx, reader, object)
}

// lookupResource looks up a resource with the given identifier. It will use the rest mapper to resolve
// the version of the GroupKind given in the identifier.
// If the resource is found, it is returned. If it is not found or something
// went wrong, the function will return an error.
func (b *baseStatusReader) lookupResource(ctx context.Context, reader engine.ClusterReader, identifier object.ObjMetadata) (*unstructured.Unstructured, error) {
	GVK, err := gvk(identifier.GroupKind, b.mapper)
	if err != nil {
		return nil, err
	}

	var u unstructured.Unstructured
	u.SetGroupVersionKind(GVK)
	key := types.NamespacedName{
		Name:      identifier.Name,
		Namespace: identifier.Namespace,
	}
	err = reader.Get(ctx, key, &u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// statusForGenResourcesFunc defines the function type used by the statusForGeneratedResource function.
// TODO: Find a better solution for this. Maybe put the logic for looking up generated resources
// into a separate type.
type statusForGenResourcesFunc func(ctx context.Context, mapper meta.RESTMapper, reader engine.ClusterReader, statusReader resourceTypeStatusReader,
	object *unstructured.Unstructured, gk schema.GroupKind, selectorPath ...string) (event.ResourceStatuses, error)

// statusForGeneratedResources provides a way to fetch the statuses for all resources of a given GroupKind
// that match the selector in the provided resource. Typically, this is used to fetch the status of generated
// resources.
func statusForGeneratedResources(ctx context.Context, mapper meta.RESTMapper, reader engine.ClusterReader, statusReader resourceTypeStatusReader,
	object *unstructured.Unstructured, gk schema.GroupKind, selectorPath ...string) (event.ResourceStatuses, error) {
	selector, err := toSelector(object, selectorPath...)
	if err != nil {
		return event.ResourceStatuses{}, err
	}

	var objectList unstructured.UnstructuredList
	gvk, err := gvk(gk, mapper)
	if err != nil {
		return event.ResourceStatuses{}, err
	}
	objectList.SetGroupVersionKind(gvk)
	err = reader.ListNamespaceScoped(ctx, &objectList, object.GetNamespace(), selector)
	if err != nil {
		return event.ResourceStatuses{}, err
	}

	var resourceStatuses event.ResourceStatuses
	for i := range objectList.Items {
		generatedObject := objectList.Items[i]
		resourceStatus, err := statusReader.ReadStatusForObject(ctx, reader, &generatedObject)
		if err != nil {
			return event.ResourceStatuses{}, err
		}
		resourceStatuses = append(resourceStatuses, resourceStatus)
	}
	sort.Sort(resourceStatuses)
	return resourceStatuses, nil
}

// gvk looks up the GVK from a GroupKind using the rest mapper.
func gvk(gk schema.GroupKind, mapper meta.RESTMapper) (schema.GroupVersionKind, error) {
	mapping, err := mapper.RESTMapping(gk)
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	return mapping.GroupVersionKind, nil
}

func toSelector(resource *unstructured.Unstructured, path ...string) (labels.Selector, error) {
	selector, found, err := unstructured.NestedMap(resource.Object, path...)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("no selector found")
	}
	bytes, err := json.Marshal(selector)
	if err != nil {
		return nil, err
	}
	var s metav1.LabelSelector
	err = json.Unmarshal(bytes, &s)
	if err != nil {
		return nil, err
	}
	return metav1.LabelSelectorAsSelector(&s)
}

// errResourceToResourceStatus construct the appropriate ResourceStatus
// object based on an error and the resource itself.
func errResourceToResourceStatus(err error, resource *unstructured.Unstructured, genResources ...*event.ResourceStatus) (*event.ResourceStatus, error) {
	// If the error is from the context, we don't attach that to the ResourceStatus,
	// but just return it directly so the caller can decide how to handle this
	// situation.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	identifier := object.UnstructuredToObjMetadata(resource)
	if apierrors.IsNotFound(err) {
		return &event.ResourceStatus{
			Identifier: identifier,
			Status:     status.NotFoundStatus,
			Message:    "Resource not found",
		}, nil
	}
	return &event.ResourceStatus{
		Identifier:         identifier,
		Status:             status.UnknownStatus,
		Resource:           resource,
		Error:              err,
		GeneratedResources: genResources,
	}, nil
}

// errIdentifierToResourceStatus construct the appropriate ResourceStatus
// object based on an error and the identifier for a resource.
func errIdentifierToResourceStatus(err error, identifier object.ObjMetadata) (*event.ResourceStatus, error) {
	// If the error is from the context, we don't attach that to the ResourceStatus,
	// but just return it directly so the caller can decide how to handle this
	// situation.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if apierrors.IsNotFound(err) {
		return &event.ResourceStatus{
			Identifier: identifier,
			Status:     status.NotFoundStatus,
			Message:    "Resource not found",
		}, nil
	}
	return &event.ResourceStatus{
		Identifier: identifier,
		Status:     status.UnknownStatus,
		Error:      err,
	}, nil
}
