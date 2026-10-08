// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/kstatus/status"
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// isObjectUnschedulable returns true if the object or any of its generated resources
// is an unschedulable pod.
//
// This status is computed recursively, so it can handle objects that generate
// objects that generate pods, as long as the input ResourceStatus has those
// GeneratedResources computed.
func isObjectUnschedulable(rs *event.ResourceStatus) bool {
	if rs.Error != nil {
		return false
	}
	if rs.Status != status.InProgressStatus {
		return false
	}
	if isPodUnschedulable(rs.Resource) {
		return true
	}
	// recurse through generated resources
	for _, subRS := range rs.GeneratedResources {
		if isObjectUnschedulable(subRS) {
			return true
		}
	}
	return false
}

// isPodUnschedulable returns true if the object is a pod and is unschedulable
// according to a False PodScheduled condition.
func isPodUnschedulable(obj *unstructured.Unstructured) bool {
	if obj == nil {
		return false
	}
	gk := obj.GroupVersionKind().GroupKind()
	if gk != (schema.GroupKind{Kind: "Pod"}) {
		return false
	}
	icnds, found, err := object.NestedField(obj.Object, "status", "conditions")
	if err != nil || !found {
		return false
	}
	cnds, ok := icnds.([]interface{})
	if !ok {
		return false
	}
	for _, icnd := range cnds {
		cnd, ok := icnd.(map[string]interface{})
		if !ok {
			return false
		}
		if cnd["type"] == "PodScheduled" &&
			cnd["status"] == "False" &&
			cnd["reason"] == "Unschedulable" {
			return true
		}
	}
	return false
}
