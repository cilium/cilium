// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
