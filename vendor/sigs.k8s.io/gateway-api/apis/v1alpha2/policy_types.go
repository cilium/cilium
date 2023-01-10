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

package v1alpha2

// PolicyTargetReference identifies an API object to apply policy to. This
// should be used as part of Policy resources that can target Gateway API
// resources. For more information on how this policy attachment model works,
// and a sample Policy resource, refer to the policy attachment documentation
// for Gateway API.
type PolicyTargetReference struct {
	// Group is the group of the target resource.
	Group Group `json:"group"`

	// Kind is kind of the target resource.
	Kind Kind `json:"kind"`

	// Name is the name of the target resource.
	Name ObjectName `json:"name"`

	// Namespace is the namespace of the referent. When unspecified, the local
	// namespace is inferred. Even when policy targets a resource in a different
	// namespace, it MUST only apply to traffic originating from the same
	// namespace as the policy.
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`
}
