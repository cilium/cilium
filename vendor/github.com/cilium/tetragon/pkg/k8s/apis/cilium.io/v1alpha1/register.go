// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package v1alpha1

import (
	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	CRDVersion = "v1alpha1"

	// TPCRDName is the full name of the TracingPolicy CRD.
	TPCRDName = TPKindDefinition + "/" + CRDVersion

	// TPNamespacedCRDName is the full name of the TracingPolicy CRD.
	TPNamespacedCRDName = TPNamespacedKindDefinition + "/" + CRDVersion

	// PICRDName is the full name of the Tetragon Pod Info CRD.
	PICRDName = PIKindDefinition + "/" + CRDVersion
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: ciliumio.GroupName, Version: CRDVersion}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	AddToScheme        = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&TracingPolicy{},
		&TracingPolicyList{},
		&TracingPolicyNamespaced{},
		&TracingPolicyNamespacedList{},
		&PodInfo{},
		&PodInfoList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
