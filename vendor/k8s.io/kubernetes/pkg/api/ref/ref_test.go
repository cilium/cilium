/*
Copyright 2014 The Kubernetes Authors.

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

package ref

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/api"
)

type FakeAPIObject struct{}

func (obj *FakeAPIObject) GetObjectKind() schema.ObjectKind { return schema.EmptyObjectKind }
func (obj *FakeAPIObject) DeepCopyObject() runtime.Object {
	if obj == nil {
		return nil
	}
	clone := *obj
	return &clone
}

type ExtensionAPIObject struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

func (obj *ExtensionAPIObject) DeepCopyObject() runtime.Object {
	panic("ExtensionAPIObject does not support DeepCopy")
}

func TestGetReference(t *testing.T) {

	// when vendoring kube, if you don't force the set of registered versions (like make test does)
	// then you run into trouble because the types aren't registered in the scheme by anything.  This does the
	// register manually to allow unit test execution
	if _, _, err := api.Scheme.ObjectKinds(&api.Pod{}); err != nil {
		api.AddToScheme(api.Scheme)
	}

	table := map[string]struct {
		obj       runtime.Object
		ref       *api.ObjectReference
		fieldPath string
		shouldErr bool
	}{
		"pod": {
			obj: &api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					UID:             "bar",
					ResourceVersion: "42",
					SelfLink:        "/api/version1/pods/foo",
				},
			},
			fieldPath: ".desiredState.containers[0]",
			ref: &api.ObjectReference{
				Kind:            "Pod",
				APIVersion:      "version1",
				Name:            "foo",
				UID:             "bar",
				ResourceVersion: "42",
				FieldPath:       ".desiredState.containers[0]",
			},
		},
		"serviceList": {
			obj: &api.ServiceList{
				ListMeta: metav1.ListMeta{
					ResourceVersion: "42",
					SelfLink:        "/api/version2/services",
				},
			},
			ref: &api.ObjectReference{
				Kind:            "ServiceList",
				APIVersion:      "version2",
				ResourceVersion: "42",
			},
		},
		"extensionAPIObject": {
			obj: &ExtensionAPIObject{
				TypeMeta: metav1.TypeMeta{
					Kind: "ExtensionAPIObject",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "foo",
					UID:             "bar",
					ResourceVersion: "42",
					SelfLink:        "/custom_prefix/version1/extensions/foo",
				},
			},
			ref: &api.ObjectReference{
				Kind:            "ExtensionAPIObject",
				APIVersion:      "version1",
				Name:            "foo",
				UID:             "bar",
				ResourceVersion: "42",
			},
		},
		"badSelfLink": {
			obj: &api.ServiceList{
				ListMeta: metav1.ListMeta{
					ResourceVersion: "42",
					SelfLink:        "version2/services",
				},
			},
			shouldErr: true,
		},
		"error": {
			obj:       &FakeAPIObject{},
			ref:       nil,
			shouldErr: true,
		},
		"errorNil": {
			obj:       nil,
			ref:       nil,
			shouldErr: true,
		},
	}

	for name, item := range table {
		ref, err := GetPartialReference(api.Scheme, item.obj, item.fieldPath)
		if e, a := item.shouldErr, (err != nil); e != a {
			t.Errorf("%v: expected %v, got %v, err %v", name, e, a, err)
			continue
		}
		if e, a := item.ref, ref; !reflect.DeepEqual(e, a) {
			t.Errorf("%v: expected %#v, got %#v", name, e, a)
		}
	}
}
