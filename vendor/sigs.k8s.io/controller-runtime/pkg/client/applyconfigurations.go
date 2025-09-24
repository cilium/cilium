/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
)

type unstructuredApplyConfiguration struct {
	*unstructured.Unstructured
}

func (u *unstructuredApplyConfiguration) IsApplyConfiguration() {}

// ApplyConfigurationFromUnstructured creates a runtime.ApplyConfiguration from an *unstructured.Unstructured object.
//
// Do not use Unstructured objects here that were generated from API objects, as its impossible to tell
// if a zero value was explicitly set.
func ApplyConfigurationFromUnstructured(u *unstructured.Unstructured) runtime.ApplyConfiguration {
	return &unstructuredApplyConfiguration{Unstructured: u}
}

type applyconfigurationRuntimeObject struct {
	runtime.ApplyConfiguration
}

func (a *applyconfigurationRuntimeObject) GetObjectKind() schema.ObjectKind {
	return a
}

func (a *applyconfigurationRuntimeObject) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{}
}

func (a *applyconfigurationRuntimeObject) SetGroupVersionKind(gvk schema.GroupVersionKind) {}

func (a *applyconfigurationRuntimeObject) DeepCopyObject() runtime.Object {
	panic("applyconfigurationRuntimeObject does not support DeepCopyObject")
}

func runtimeObjectFromApplyConfiguration(ac runtime.ApplyConfiguration) runtime.Object {
	return &applyconfigurationRuntimeObject{ApplyConfiguration: ac}
}

func gvkFromApplyConfiguration(ac applyConfiguration) (schema.GroupVersionKind, error) {
	var gvk schema.GroupVersionKind
	gv, err := schema.ParseGroupVersion(ptr.Deref(ac.GetAPIVersion(), ""))
	if err != nil {
		return gvk, fmt.Errorf("failed to parse %q as GroupVersion: %w", ptr.Deref(ac.GetAPIVersion(), ""), err)
	}
	gvk.Group = gv.Group
	gvk.Version = gv.Version
	gvk.Kind = ptr.Deref(ac.GetKind(), "")

	return gvk, nil
}
