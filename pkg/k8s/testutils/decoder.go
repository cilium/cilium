// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"os"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapi_fake "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned/fake"

	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slim_apiextclientsetscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/apiextensions-client/clientset/versioned/scheme"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
)

var (
	// Scheme for object types used in Cilium.
	// The scheme can be extended by init() functions since [Decoder] is
	// lazily constructed.
	Scheme = runtime.NewScheme()

	decoderOnce sync.Once
	decoder     runtime.Decoder
)

// Decoder returns an object decoder for Cilium and Slim objects.
// The [DecodeObject] and [DecodeFile] functions are provided as
// shorthands for decoding from bytes and files respectively.
func Decoder() runtime.Decoder {
	decoderOnce.Do(func() {
		decoder = serializer.NewCodecFactory(Scheme).UniversalDeserializer()
	})
	return decoder
}

func init() {
	// Add corev1, discovery* and networking.
	slim_fake.AddToScheme(Scheme)

	// Add apiextensionsv1
	slim_apiextclientsetscheme.AddToScheme(Scheme)

	// Add ciliumv2 and ciliumv2alpha1
	cilium_fake.AddToScheme(Scheme)

	// Add gateway*
	gatewayv1.Install(Scheme)
	gatewayv1alpha2.Install(Scheme)
	gatewayv1beta1.Install(Scheme)

	// Add multiclusterv1alpha1
	mcsapi_fake.AddToScheme(Scheme)
}

func DecodeObject(bytes []byte) (runtime.Object, error) {
	obj, _, err := Decoder().Decode(bytes, nil, nil)
	return obj, err
}

func DecodeFile(path string) (runtime.Object, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeObject(bs)
}
