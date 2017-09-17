/*
Copyright 2014 The Kubernetes Authors.

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

package limitranger

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/kubernetes/pkg/api"
)

type LimitRangerActions interface {
	// Limit is a pluggable function to enforce limits on the object.
	Limit(limitRange *api.LimitRange, kind string, obj runtime.Object) error
	// SupportsAttributes is a pluggable function to allow overridding what resources the limitranger
	// supports.
	SupportsAttributes(attr admission.Attributes) bool
	// SupportsLimit is a pluggable function to allow ignoring limits that should not be applied
	// for any reason.
	SupportsLimit(limitRange *api.LimitRange) bool
}
