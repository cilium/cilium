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

package v1

// LocalObjectReference identifies an API object within the namespace of the
// referrer.
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
//
// References to objects with invalid Group and Kind are not valid, and must
// be rejected by the implementation, with appropriate Conditions set
// on the containing object.
type LocalObjectReference struct {
	// Group is the group of the referent. For example, "gateway.networking.k8s.io".
	// When unspecified or empty string, core API group is inferred.
	// +required
	Group Group `json:"group"`

	// Kind is kind of the referent. For example "HTTPRoute" or "Service".
	// +required
	Kind Kind `json:"kind"`

	// Name is the name of the referent.
	// +required
	Name ObjectName `json:"name"`
}

// SecretObjectReference identifies an API object including its namespace,
// defaulting to Secret.
//
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
//
// References to objects with invalid Group and Kind are not valid, and must
// be rejected by the implementation, with appropriate Conditions set
// on the containing object.
type SecretObjectReference struct {
	// Group is the group of the referent. For example, "gateway.networking.k8s.io".
	// When unspecified or empty string, core API group is inferred.
	//
	// +optional
	// +kubebuilder:default=""
	Group *Group `json:"group"`

	// Kind is kind of the referent. For example "Secret".
	//
	// +optional
	// +kubebuilder:default=Secret
	Kind *Kind `json:"kind"`

	// Name is the name of the referent.
	// +required
	Name ObjectName `json:"name"`

	// Namespace is the namespace of the referenced object. When unspecified, the local
	// namespace is inferred.
	//
	// Note that when a namespace different than the local namespace is specified,
	// a ReferenceGrant object is required in the referent namespace to allow that
	// namespace's owner to accept the reference. See the ReferenceGrant
	// documentation for details.
	//
	// Support: Core
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`
}

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
//
// +kubebuilder:validation:XValidation:message="Must have port for Service reference",rule="(size(self.group) == 0 && self.kind == 'Service') ? has(self.port) : true"
type BackendObjectReference struct {
	// Group is the group of the referent. For example, "gateway.networking.k8s.io".
	// When unspecified or empty string, core API group is inferred.
	//
	// +optional
	// +kubebuilder:default=""
	Group *Group `json:"group,omitempty"`

	// Kind is the Kubernetes resource kind of the referent. For example
	// "Service".
	//
	// Defaults to "Service" when not specified.
	//
	// ExternalName services can refer to CNAME DNS records that may live
	// outside of the cluster and as such are difficult to reason about in
	// terms of conformance. They also may not be safe to forward to (see
	// CVE-2021-25740 for more information). Implementations SHOULD NOT
	// support ExternalName Services.
	//
	// Support: Core (Services with a type other than ExternalName)
	//
	// Support: Implementation-specific (Services with type ExternalName)
	//
	// +optional
	// +kubebuilder:default=Service
	Kind *Kind `json:"kind,omitempty"`

	// Name is the name of the referent.
	// +required
	Name ObjectName `json:"name"`

	// Namespace is the namespace of the backend. When unspecified, the local
	// namespace is inferred.
	//
	// Note that when a namespace different than the local namespace is specified,
	// a ReferenceGrant object is required in the referent namespace to allow that
	// namespace's owner to accept the reference. See the ReferenceGrant
	// documentation for details.
	//
	// Support: Core
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`

	// Port specifies the destination port number to use for this resource.
	// Port is required when the referent is a Kubernetes Service. In this
	// case, the port number is the service port number, not the target port.
	// For other resources, destination port might be derived from the referent
	// resource or this field.
	//
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port *PortNumber `json:"port,omitempty"`
}

// ObjectReference identifies an API object including its namespace.
//
// The API object must be valid in the cluster; the Group and Kind must
// be registered in the cluster for this reference to be valid.
//
// References to objects with invalid Group and Kind are not valid, and must
// be rejected by the implementation, with appropriate Conditions set
// on the containing object.
type ObjectReference struct {
	// Group is the group of the referent. For example, "gateway.networking.k8s.io".
	// When set to the empty string, core API group is inferred.
	// +required
	Group Group `json:"group"`

	// Kind is kind of the referent. For example "ConfigMap" or "Service".
	// +required
	Kind Kind `json:"kind"`

	// Name is the name of the referent.
	// +required
	Name ObjectName `json:"name"`

	// Namespace is the namespace of the referenced object. When unspecified, the local
	// namespace is inferred.
	//
	// Note that when a namespace different than the local namespace is specified,
	// a ReferenceGrant object is required in the referent namespace to allow that
	// namespace's owner to accept the reference. See the ReferenceGrant
	// documentation for details.
	//
	// Support: Core
	//
	// +optional
	Namespace *Namespace `json:"namespace,omitempty"`
}
