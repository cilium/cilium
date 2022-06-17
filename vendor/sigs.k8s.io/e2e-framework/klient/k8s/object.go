/*
Copyright 2021 The Kubernetes Authors.

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

package k8s

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// Object is a union type that can represent either typed objects
// of type metav1.Object or dynamic objects of type runtime.object.
type Object interface {
	metav1.Object
	runtime.Object
}

// ObjectList is a Kubernetes object list, allows functions to work
// with any resource that implements both runtime.Object and
// metav1.ListInterface interfaces.
type ObjectList interface {
	metav1.ListInterface
	runtime.Object
}

// Patch is a patch that can be applied to a Kubernetes object.
type Patch struct {
	// PatchType is the type of the patch.
	PatchType types.PatchType
	// Data is the raw data representing the patch.
	Data []byte
}
