// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/fake"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
)

//
// Marshalling utilities for control-plane tests.
//
// While we could have one decoder for all kinds, we need separate decoders
// to know to which ObjectTracker to hand the decoded object to.
//
// We use CodecFactory's UniversalDeserializer instead of Scheme.Convert as the
// Cilium CRDs have unexported fields and need to be decoded using their
// custom UnmarshalJSON functions.

var (
	// coreDecoder decodes objects using only the corev1 scheme
	coreDecoder k8sRuntime.Decoder

	// slimDecoder decodes objects with the slim scheme
	slimDecoder k8sRuntime.Decoder

	// ciliumDecoder decodes objects with the cilium v2 scheme
	ciliumDecoder k8sRuntime.Decoder
)

func init() {
	coreScheme := k8sRuntime.NewScheme()
	fake.AddToScheme(coreScheme)
	coreDecoder = serializer.NewCodecFactory(coreScheme).UniversalDeserializer()

	slimScheme := k8sRuntime.NewScheme()
	slim_fake.AddToScheme(slimScheme)
	slimScheme.AddKnownTypes(slim_corev1.SchemeGroupVersion, &metav1.List{})
	slimDecoder = serializer.NewCodecFactory(slimScheme).UniversalDeserializer()

	ciliumScheme := k8sRuntime.NewScheme()
	cilium_v2.AddToScheme(ciliumScheme)
	ciliumDecoder = serializer.NewCodecFactory(ciliumScheme).UniversalDeserializer()
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
