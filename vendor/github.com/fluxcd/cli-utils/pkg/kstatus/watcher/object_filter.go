// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"github.com/fluxcd/cli-utils/pkg/object"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ObjectFilter allows for filtering objects.
type ObjectFilter interface {
	// Filter returns true if the object should be skipped.
	Filter(obj *unstructured.Unstructured) bool
}

// AllowListObjectFilter filters objects not in the allow list.
// AllowListObjectFilter implements ObjectFilter.
type AllowListObjectFilter struct {
	AllowList object.ObjMetadataSet
}

var _ ObjectFilter = &AllowListObjectFilter{}

// Filter returns true if the object should be skipped, because it is NOT in the
// AllowList.
func (f *AllowListObjectFilter) Filter(obj *unstructured.Unstructured) bool {
	id := object.UnstructuredToObjMetadata(obj)
	return !f.AllowList.Contains(id)
}
