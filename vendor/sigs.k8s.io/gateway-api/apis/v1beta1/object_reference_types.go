/*
Copyright 2020 The Kubernetes Authors.

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

package v1beta1

import v1 "sigs.k8s.io/gateway-api/apis/v1"

// LocalObjectReference identifies an API object within the namespace of the
// referrer.
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
//
// References to objects with invalid Group and Kind are not valid, and must
// be rejected by the implementation, with appropriate Conditions set
// on the containing object.
// +k8s:deepcopy-gen=false
type LocalObjectReference = v1.LocalObjectReference

// SecretObjectReference identifies an API object including its namespace,
// defaulting to Secret.
//
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
//
// References to objects with invalid Group and Kind are not valid, and must
// be rejected by the implementation, with appropriate Conditions set
// on the containing object.
// +k8s:deepcopy-gen=false
type SecretObjectReference = v1.SecretObjectReference

// BackendObjectReference defines how an ObjectReference that is
// specific to BackendRef. It includes a few additional fields and features
// than a regular ObjectReference.
//
// Note that when a namespace different than the local namespace is specified, a
// ReferenceGrant object is required in the referent namespace to allow that
// namespace's owner to accept the reference. See the ReferenceGrant
// documentation for details.
//
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
//
// References to objects with invalid Group and Kind are not valid, and must
// be rejected by the implementation, with appropriate Conditions set
// on the containing object.
// +k8s:deepcopy-gen=false
type BackendObjectReference = v1.BackendObjectReference
