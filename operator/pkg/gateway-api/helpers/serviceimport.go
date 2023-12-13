// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/types"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsapicontrollers "sigs.k8s.io/mcs-api/pkg/controllers"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var hasServiceImportCRD bool = false

// HasServiceImportCRD return if the ServiceImport CRD is installed.
// This does not do a dynamic check but return the value of the
// last CheckServiceImportCRD call which is normally called once during init.
func HasServiceImportCRD() bool {
	return hasServiceImportCRD
}

// CheckServiceImportCRD check if the MCS API ServiceImport CRD is installed.
// It is normally called during init (or testing) and is used to setup the value
// returned by the HasServiceImportCRD function.
func CheckServiceImportCRD(ctx context.Context, client client.Client) {
	gvk := mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceimports")
	key := types.NamespacedName{Name: gvk.GroupKind().String()}
	crd := &apiextensionsv1.CustomResourceDefinition{}
	if err := client.Get(ctx, key, crd); err != nil {
		hasServiceImportCRD = false
		return
	}

	for _, v := range crd.Spec.Versions {
		if v.Name == gvk.Version {
			hasServiceImportCRD = true
			return
		}
	}

	hasServiceImportCRD = false
}

func GetServiceName(svcImport *mcsapiv1alpha1.ServiceImport) (string, error) {
	// ServiceImport gateway api support is conditioned by the fact
	// that an actual Service backs it. Other implementations of MCS API
	// are not supported.
	backendServiceName, ok := svcImport.Annotations[mcsapicontrollers.DerivedServiceAnnotation]
	if !ok {
		return "", fmt.Errorf("%s %s/%s does not have annotation %s", svcImport.Kind, svcImport.Namespace, svcImport.Name, mcsapicontrollers.DerivedServiceAnnotation)
	}

	return backendServiceName, nil
}
