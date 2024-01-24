// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetBackendServiceName(k8sclient client.Client, namespace string, backendObjectReference gatewayv1.BackendObjectReference) (string, error) {
	backendServiceName := ""
	switch {
	case IsService(backendObjectReference):
		return string(backendObjectReference.Name), nil

	case HasServiceImportSupport(k8sclient.Scheme()) && IsServiceImport(backendObjectReference):
		svcImport := &mcsapiv1alpha1.ServiceImport{}
		if err := k8sclient.Get(context.Background(), client.ObjectKey{
			Namespace: namespace,
			Name:      string(backendObjectReference.Name),
		}, svcImport); err != nil {
			return "", err
		}

		var err error
		backendServiceName, err = GetServiceName(svcImport)
		if err != nil {
			return "", err
		}

	default:
		return "", fmt.Errorf("Unsupported backend kind %s", *backendObjectReference.Kind)
	}

	return backendServiceName, nil
}
