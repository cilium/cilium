// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/fake"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
)

//
// Marshalling utilities for control-plane tests.
//

var (
	// coreDecoder decodes objects using only the corev1 scheme
	coreDecoder = newCoreSchemeDecoder()

	// slimDecoder decodes objects with the slim scheme
	slimDecoder = newSlimSchemeDecoder()

	// ciliumDecoder decodes objects with the cilium v2 scheme
	ciliumDecoder = newCiliumSchemeDecoder()
)

type schemeDecoder struct {
	*k8sRuntime.Scheme
}

func (d schemeDecoder) unmarshal(in string) (k8sRuntime.Object, error) {
	var obj unstructured.Unstructured
	err := yaml.Unmarshal([]byte(in), &obj)
	if err != nil {
		return nil, err
	}
	return d.convert(&obj)
}

// known returns true if the object kind is known to the scheme,
// e.g. it can decode it.
func (d schemeDecoder) known(obj k8sRuntime.Object) bool {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return d.Scheme.Recognizes(gvk)
}

// convert converts the input object (usually Unstructured) using
// the scheme.
func (d schemeDecoder) convert(obj k8sRuntime.Object) (k8sRuntime.Object, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	out, err := d.Scheme.ConvertToVersion(obj, gvk.GroupVersion())
	if err != nil {
		return nil, err
	}
	return out, err
}

func newSlimSchemeDecoder() schemeDecoder {
	s := k8sRuntime.NewScheme()
	slim_fake.AddToScheme(s)
	s.AddKnownTypes(slim_corev1.SchemeGroupVersion, &metav1.List{})
	return schemeDecoder{s}
}

func newCiliumSchemeDecoder() schemeDecoder {
	s := k8sRuntime.NewScheme()
	cilium_v2.AddToScheme(s)
	return schemeDecoder{s}
}

func newCoreSchemeDecoder() schemeDecoder {
	s := k8sRuntime.NewScheme()
	fake.AddToScheme(s)
	return schemeDecoder{s}
}

// unmarshalList unmarshals the input yaml data into an unstructured list.
func unmarshalList(bs []byte) ([]k8sRuntime.Object, error) {
	var items unstructured.UnstructuredList
	err := yaml.Unmarshal(bs, &items)
	if err != nil {
		return nil, err
	}
	var objs []k8sRuntime.Object
	items.EachListItem(func(obj k8sRuntime.Object) error {
		objs = append(objs, obj)
		return nil
	})
	return objs, nil

}
