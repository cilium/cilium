// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CheckCRD checks if the given CRD exists and has the specified version.
func CheckCRD(ctx context.Context, clientset Clientset, gvk schema.GroupVersionKind) error {
	if !clientset.IsEnabled() {
		return nil
	}

	crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, gvk.GroupKind().String(), metav1.GetOptions{})
	if err != nil {
		return err
	}

	found := false
	for _, v := range crd.Spec.Versions {
		if v.Name == gvk.Version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("CRD %q does not have version %q", gvk.GroupKind().String(), gvk.Version)
	}

	return nil
}
