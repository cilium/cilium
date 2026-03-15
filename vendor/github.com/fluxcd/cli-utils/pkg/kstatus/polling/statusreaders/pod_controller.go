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
	corev1 "k8s.io/api/core/v1"
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
	// none of them have terminally failed. Pods that are pending scheduling are
	// excluded, as this is a transient state that cluster autoscalers can resolve.
	// Pods that are being deleted (e.g. during a rolling update) are also excluded.
	if res.Status == status.InProgressStatus {
		var failedPods []*event.ResourceStatus
		for _, podResourceStatus := range podResourceStatuses {
			if podResourceStatus.Status == status.FailedStatus {
				if isTransientPodFailure(podResourceStatus) {
					continue
				}
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

// isTransientPodFailure returns true if the pod's failure is likely transient
// and should not cause the parent controller to be marked as failed. This
// includes pods that are pending scheduling (which an autoscaler may resolve)
// and pods that are being deleted (during a rolling update).
func isTransientPodFailure(podStatus *event.ResourceStatus) bool {
	pod := podStatus.Resource
	if pod == nil {
		// If the resource is not available, we cannot determine whether the
		// failure is transient. Treat it as transient to avoid prematurely
		// marking the parent controller as failed.
		return true
	}

	// Pods being deleted are expected during rolling updates.
	if pod.GetDeletionTimestamp() != nil {
		return true
	}

	// Pods that are pending scheduling due to insufficient resources are
	// transient failures that a cluster autoscaler can resolve.
	if isPodUnschedulable(pod) {
		return true
	}

	return false
}

// isPodUnschedulable returns true if the object is a pod with a PodScheduled
// condition indicating it is Unschedulable.
func isPodUnschedulable(obj *unstructured.Unstructured) bool {
	gk := obj.GroupVersionKind().GroupKind()
	if gk != (schema.GroupKind{Kind: "Pod"}) {
		return false
	}
	objWithConditions, err := status.GetObjectWithConditions(obj.Object)
	if err != nil {
		return false
	}
	for _, cond := range objWithConditions.Status.Conditions {
		if cond.Type == string(corev1.PodScheduled) &&
			cond.Status == corev1.ConditionFalse &&
			cond.Reason == corev1.PodReasonUnschedulable {
			return true
		}
	}
	return false
}
