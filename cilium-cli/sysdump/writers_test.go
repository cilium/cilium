// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/client-go/kubernetes/scheme"
)

func TestWriteYaml(t *testing.T) {
	newObj := func(i int) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:        fmt.Sprintf("foo-%d", i),
				Labels:      map[string]string{"label": "value"},
				Annotations: map[string]string{"anno": "value"},
			},
			Data: map[string]string{
				"foo": "bar",
				"baz": "qux",
			},
		}
	}

	tests := []struct {
		name string
		obj  func() runtime.Object
	}{
		{
			name: "single object",
			obj: func() runtime.Object {
				return newObj(0)
			},
		},
		{
			name: "list w/o resource version",
			obj: func() runtime.Object {
				var obj corev1.ConfigMapList
				for i := range 10 {
					obj.Items = append(obj.Items, *newObj(i))
				}
				return &obj
			},
		},
		{
			name: "list w/ resource version",
			obj: func() runtime.Object {
				var obj corev1.ConfigMapList
				for i := range 10 {
					obj.Items = append(obj.Items, *newObj(i))
				}
				obj.SetResourceVersion("111")
				return &obj
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expected, got bytes.Buffer
			obj := tt.obj()

			printer, _ := printers.NewTypeSetter(scheme.Scheme).
				WrapToPrinter(&printers.YAMLPrinter{}, nil)
			require.NoError(t, printer.PrintObj(obj, &expected))
			require.NoError(t, writeYAML(obj, &got))
			require.Equal(t, expected.String(), got.String())
		})
	}
}
