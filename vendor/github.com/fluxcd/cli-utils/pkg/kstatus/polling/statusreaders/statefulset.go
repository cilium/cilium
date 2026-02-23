// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package statusreaders

import (
	"context"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func NewStatefulSetResourceReader(mapper meta.RESTMapper, podResourceReader resourceTypeStatusReader) engine.StatusReader {
	return &baseStatusReader{
		mapper: mapper,
		resourceStatusReader: &statefulSetResourceReader{
			mapper:            mapper,
			podResourceReader: podResourceReader,
		},
	}
}

// statefulSetResourceReader is an implementation of the ResourceReader interface
// that can fetch StatefulSet resources from the cluster, knows how to find any
// Pods belonging to the StatefulSet, and compute status for the StatefulSet.
type statefulSetResourceReader struct {
	mapper meta.RESTMapper

	podResourceReader resourceTypeStatusReader
}

var _ resourceTypeStatusReader = &statefulSetResourceReader{}

func (s *statefulSetResourceReader) Supports(gk schema.GroupKind) bool {
	return gk == appsv1.SchemeGroupVersion.WithKind("StatefulSet").GroupKind()
}

func (s *statefulSetResourceReader) ReadStatusForObject(ctx context.Context, reader engine.ClusterReader,
	statefulSet *unstructured.Unstructured) (*event.ResourceStatus, error) {
	return newPodControllerStatusReader(s.mapper, s.podResourceReader).readStatus(ctx, reader, statefulSet)
}
