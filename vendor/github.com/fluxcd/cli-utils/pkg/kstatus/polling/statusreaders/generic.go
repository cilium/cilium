// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package statusreaders

import (
	"context"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// StatusFunc returns the status of the given object. This func is passed into
// NewGenericStatusReader so that the returned StatusReader can be used for custom types.
// An example of a StatusFunc is status.Compute.
type StatusFunc func(u *unstructured.Unstructured) (*status.Result, error)

func NewGenericStatusReader(mapper meta.RESTMapper, statusFunc StatusFunc) engine.StatusReader {
	return &baseStatusReader{
		mapper: mapper,
		resourceStatusReader: &genericStatusReader{
			mapper:     mapper,
			statusFunc: statusFunc,
		},
	}
}

// genericStatusReader is a resourceTypeStatusReader that will be used for
// any resource that doesn't have a specific engine. It will just delegate
// computation of status to the status library.
// This should work pretty well for resources that doesn't have any
// generated resources and where status can be computed only based on the
// resource itself.
type genericStatusReader struct {
	mapper meta.RESTMapper

	statusFunc StatusFunc
}

var _ resourceTypeStatusReader = &genericStatusReader{}

func (g *genericStatusReader) Supports(schema.GroupKind) bool {
	return true
}

func (g *genericStatusReader) ReadStatusForObject(_ context.Context, _ engine.ClusterReader, resource *unstructured.Unstructured) (*event.ResourceStatus, error) {
	identifier := object.UnstructuredToObjMetadata(resource)

	res, err := g.statusFunc(resource)
	if err != nil {
		return errResourceToResourceStatus(err, resource)
	}

	return &event.ResourceStatus{
		Identifier: identifier,
		Status:     res.Status,
		Resource:   resource,
		Message:    res.Message,
	}, nil
}
