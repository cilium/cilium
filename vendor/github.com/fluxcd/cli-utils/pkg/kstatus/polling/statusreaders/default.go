// Copyright 2021 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package statusreaders

import (
	"context"
	"fmt"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NewDefaultStatusReader returns a DelegatingStatusReader that wraps a list of
// statusreaders to cover all built-in Kubernetes resources and other CRDs that
// follow known status conventions.
func NewDefaultStatusReader(mapper meta.RESTMapper) engine.StatusReader {
	return NewStatusReader(mapper)
}

// NewStatusReader returns a DelegatingStatusReader that includes the statusreaders
// for the build-in Kubernetes resources and also any provided custom status readers.
func NewStatusReader(mapper meta.RESTMapper, statusReaders ...engine.StatusReader) engine.StatusReader {
	defaultStatusReader := NewGenericStatusReader(mapper, status.Compute)

	replicaSetStatusReader := NewReplicaSetStatusReader(mapper, defaultStatusReader)
	deploymentStatusReader := NewDeploymentResourceReader(mapper, replicaSetStatusReader)
	statefulSetStatusReader := NewStatefulSetResourceReader(mapper, defaultStatusReader)

	statusReaders = append(statusReaders,
		deploymentStatusReader,
		statefulSetStatusReader,
		replicaSetStatusReader,
		defaultStatusReader,
	)

	return &DelegatingStatusReader{
		StatusReaders: statusReaders,
	}
}

type DelegatingStatusReader struct {
	StatusReaders []engine.StatusReader
}

func (dsr *DelegatingStatusReader) Supports(gk schema.GroupKind) bool {
	for _, sr := range dsr.StatusReaders {
		if sr.Supports(gk) {
			return true
		}
	}
	return false
}

func (dsr *DelegatingStatusReader) ReadStatus(
	ctx context.Context,
	reader engine.ClusterReader,
	id object.ObjMetadata,
) (*event.ResourceStatus, error) {
	gk := id.GroupKind
	for _, sr := range dsr.StatusReaders {
		if sr.Supports(gk) {
			return sr.ReadStatus(ctx, reader, id)
		}
	}
	return nil, fmt.Errorf("no status reader supports this resource: %v", gk)
}

func (dsr *DelegatingStatusReader) ReadStatusForObject(
	ctx context.Context,
	reader engine.ClusterReader,
	obj *unstructured.Unstructured,
) (*event.ResourceStatus, error) {
	gk := obj.GroupVersionKind().GroupKind()
	for _, sr := range dsr.StatusReaders {
		if sr.Supports(gk) {
			return sr.ReadStatusForObject(ctx, reader, obj)
		}
	}
	return nil, fmt.Errorf("no status reader supports this resource: %v", gk)
}
