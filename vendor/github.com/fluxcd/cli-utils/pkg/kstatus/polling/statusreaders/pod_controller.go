// Copyright 2020 The Kubernetes Authors.
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

func newPodControllerStatusReader(mapper meta.RESTMapper, podStatusReader resourceTypeStatusReader) *podControllerStatusReader {
	return &podControllerStatusReader{
		mapper:          mapper,
		podStatusReader: podStatusReader,
		groupKind: schema.GroupKind{
			Group: "",
			Kind:  "Pod",
		},
		statusFunc:                status.Compute,
		statusForGenResourcesFunc: statusForGeneratedResources,
	}
}

// podControllerStatusReader encapsulates the logic needed to compute the status
// for resource types that act as controllers for pods. This is quite common, so
// the logic is here instead of duplicated in each resource specific StatusReader.
type podControllerStatusReader struct {
	mapper          meta.RESTMapper
	podStatusReader resourceTypeStatusReader
	groupKind       schema.GroupKind

	statusFunc func(u *unstructured.Unstructured) (*status.Result, error)
	// TODO(mortent): See if we can avoid this. For now it is useful for testing.
	statusForGenResourcesFunc statusForGenResourcesFunc
}

func (p *podControllerStatusReader) readStatus(ctx context.Context, reader engine.ClusterReader, obj *unstructured.Unstructured) (*event.ResourceStatus, error) {
	identifier := object.UnstructuredToObjMetadata(obj)

	podResourceStatuses, err := p.statusForGenResourcesFunc(ctx, p.mapper, reader, p.podStatusReader, obj,
		p.groupKind, "spec", "selector")
	if err != nil {
		return errResourceToResourceStatus(err, obj)
	}

	res, err := p.statusFunc(obj)
	if err != nil {
		return errResourceToResourceStatus(err, obj, podResourceStatuses...)
	}

	// If the status comes back as pending, we take a look at the pods to make sure
	// none of them are in the failed state. If at least one of them are, then
	// it is unlikely (but not impossible) that the status of the PodController will become
	// Current without some kind of intervention.
	if res.Status == status.InProgressStatus {
		var failedPods []*event.ResourceStatus
		for _, podResourceStatus := range podResourceStatuses {
			if podResourceStatus.Status == status.FailedStatus {
				failedPods = append(failedPods, podResourceStatus)
			}
		}
		if len(failedPods) > 0 {
			return &event.ResourceStatus{
				Identifier:         identifier,
				Status:             status.FailedStatus,
				Resource:           obj,
				Message:            fmt.Sprintf("%d pods have failed", len(failedPods)),
				GeneratedResources: podResourceStatuses,
			}, nil
		}
	}

	return &event.ResourceStatus{
		Identifier:         identifier,
		Status:             res.Status,
		Resource:           obj,
		Message:            res.Message,
		GeneratedResources: podResourceStatuses,
	}, nil
}
