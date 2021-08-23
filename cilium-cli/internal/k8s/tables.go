// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package k8s

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func unstructuredToTable(o runtime.Object) (*metav1.Table, error) {
	if metav1.SchemeGroupVersion.WithKind("Table") != o.GetObjectKind().GroupVersionKind() {
		return nil, fmt.Errorf("failed to decode non-Table object")
	}
	u, ok := o.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("failed to decode non-Unstructured object")
	}
	t := &metav1.Table{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, t); err != nil {
		return nil, err
	}
	for i := range t.Rows {
		row := &t.Rows[i]
		if row.Object.Raw == nil || row.Object.Object != nil {
			continue
		}
		converted, err := runtime.Decode(unstructured.UnstructuredJSONScheme, row.Object.Raw)
		if err != nil {
			return nil, err
		}
		row.Object.Object = converted
	}
	return t, nil
}
