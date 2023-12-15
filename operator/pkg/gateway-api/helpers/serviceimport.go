// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsapicontrollers "sigs.k8s.io/mcs-api/pkg/controllers"
)

// HasServiceImportSupport return if the ServiceImport CRD is supported.
// This checks if the MCS API group is registered in the client scheme
// and it is expected that it is registered only if the ServiceImport
// CRD has been installed prior to the client setup.
func HasServiceImportSupport(scheme *runtime.Scheme) bool {
	return scheme.IsGroupRegistered(mcsapiv1alpha1.GroupVersion.Group)
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
