// Copyright 2020 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package statusreaders

import (
	"context"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/engine"
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/cli-utils/pkg/object"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func NewDeploymentResourceReader(mapper meta.RESTMapper, rsStatusReader resourceTypeStatusReader) engine.StatusReader {
	return &baseStatusReader{
		mapper: mapper,
		resourceStatusReader: &deploymentResourceReader{
			mapper:         mapper,
			rsStatusReader: rsStatusReader,
		},
	}
}

// deploymentResourceReader is a resourceTypeStatusReader that can fetch Deployment
// resources from the cluster, knows how to find any ReplicaSets belonging to the
// Deployment, and compute status for the deployment.
type deploymentResourceReader struct {
	mapper meta.RESTMapper

	// rsStatusReader is the implementation of the resourceTypeStatusReader
	// the knows how to compute the status for ReplicaSets.
	rsStatusReader resourceTypeStatusReader
}

var _ resourceTypeStatusReader = &deploymentResourceReader{}

func (d *deploymentResourceReader) Supports(gk schema.GroupKind) bool {
	return gk == appsv1.SchemeGroupVersion.WithKind("Deployment").GroupKind()
}

func (d *deploymentResourceReader) ReadStatusForObject(ctx context.Context, reader engine.ClusterReader,
	deployment *unstructured.Unstructured) (*event.ResourceStatus, error) {
	identifier := object.UnstructuredToObjMetadata(deployment)

	replicaSetStatuses, err := statusForGeneratedResources(ctx, d.mapper, reader, d.rsStatusReader, deployment,
		appsv1.SchemeGroupVersion.WithKind("ReplicaSet").GroupKind(), "spec", "selector")
	if err != nil {
		return errResourceToResourceStatus(err, deployment)
	}

	// Currently this engine just uses the status library for computing
	// status for the deployment. But we do have the status and state for all
	// ReplicaSets and Pods in the ObservedReplicaSets data structure, so the
	// rules can be improved to take advantage of this information.
	res, err := status.Compute(deployment)
	if err != nil {
		return errResourceToResourceStatus(err, deployment, replicaSetStatuses...)
	}

	return &event.ResourceStatus{
		Identifier:         identifier,
		Status:             res.Status,
		Resource:           deployment,
		Message:            res.Message,
		GeneratedResources: replicaSetStatuses,
	}, nil
}
