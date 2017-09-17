/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubectl

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/api"
)

func TestNamespaceGenerate(t *testing.T) {
	tests := []struct {
		params    map[string]interface{}
		expected  *api.Namespace
		expectErr bool
		index     int
	}{
		{
			params: map[string]interface{}{
				"name": "foo",
			},
			expected: &api.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			expectErr: false,
		},
		{
			params:    map[string]interface{}{},
			expectErr: true,
		},
		{
			params: map[string]interface{}{
				"name": 1,
			},
			expectErr: true,
		},
		{
			params: map[string]interface{}{
				"name": "",
			},
			expectErr: true,
		},
		{
			params: map[string]interface{}{
				"name": nil,
			},
			expectErr: true,
		},
		{
			params: map[string]interface{}{
				"name_wrong_key": "some_value",
			},
			expectErr: true,
		},
		{
			params: map[string]interface{}{
				"NAME": "some_value",
			},
			expectErr: true,
		},
	}
	generator := NamespaceGeneratorV1{}
	for index, test := range tests {
		obj, err := generator.Generate(test.params)
		switch {
		case test.expectErr && err != nil:
			continue // loop, since there's no output to check
		case test.expectErr && err == nil:
			t.Errorf("%v: expected error and didn't get one", index)
			continue // loop, no expected output object
		case !test.expectErr && err != nil:
			t.Errorf("%v: unexpected error %v", index, err)
			continue // loop, no output object
		case !test.expectErr && err == nil:
			// do nothing and drop through
		}
		if !reflect.DeepEqual(obj.(*api.Namespace), test.expected) {
			t.Errorf("\nexpected:\n%#v\nsaw:\n%#v", test.expected, obj.(*api.Namespace))
		}
	}
}
