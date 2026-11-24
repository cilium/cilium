// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ErrCRDVersionNotFound is returned by CheckCRD when the CRD exists in the
// cluster but does not serve the requested API version.
var ErrCRDVersionNotFound = errors.New("CRD version not found")

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
		return fmt.Errorf("CRD %q does not have version %q: %w", gvk.GroupKind().String(), gvk.Version, ErrCRDVersionNotFound)
	}

	return nil
}
