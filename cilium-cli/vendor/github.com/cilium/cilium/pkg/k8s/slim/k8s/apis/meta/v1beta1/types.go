// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 The Kubernetes Authors.

// package v1beta1 is alpha objects from meta that will be introduced.
package v1beta1

import (
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// PartialObjectMetadata is a generic representation of any object with ObjectMeta. It allows clients
// to get access to a particular ObjectMeta schema without knowing the details of the version.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type PartialObjectMetadata = v1.PartialObjectMetadata

// IMPORTANT: PartialObjectMetadataList has different protobuf field ids in v1beta1 than
// v1 because ListMeta was accidentally omitted prior to 1.15. Therefore this type must
// remain independent of v1.PartialObjectMetadataList to preserve mappings.

// PartialObjectMetadataList contains a list of objects containing only their metadata.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type PartialObjectMetadataList struct {
	v1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
	// +optional
	v1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,2,opt,name=metadata"`

	// items contains each of the included items.
	Items []v1.PartialObjectMetadata `json:"items" protobuf:"bytes,1,rep,name=items"`
}
