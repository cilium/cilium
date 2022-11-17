// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2014 The Kubernetes Authors.

package v1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// GroupName is the group name for this API.
const GroupName = "meta.k8s.io"

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1"}

// Unversioned is group version for unversioned API objects
// TODO: this should be v1 probably
var Unversioned = schema.GroupVersion{Group: "", Version: "v1"}

// Kind takes an unqualified kind and returns a Group qualified GroupKind
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// scheme is the registry for the common types that adhere to the meta v1 API spec.
var scheme = runtime.NewScheme()

// ParameterCodec knows about query parameters used with the meta v1 API spec.
var ParameterCodec = runtime.NewParameterCodec(scheme)

// AddMetaToScheme registers base meta types into schemas.
func AddMetaToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&PartialObjectMetadata{},
		&PartialObjectMetadataList{},
	)

	return nil
}

func init() {
	scheme.AddUnversionedTypes(SchemeGroupVersion)

	utilruntime.Must(AddMetaToScheme(scheme))

}
