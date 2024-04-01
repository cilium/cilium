/*
Copyright 2018 The Kubernetes Authors.

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

// Package apiutil contains utilities for working with raw Kubernetes
// API machinery, such as creating RESTMappers and raw REST clients,
// and extracting the GVK of an object.
package apiutil

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

var (
	protobufScheme     = runtime.NewScheme()
	protobufSchemeLock sync.RWMutex
)

func init() {
	// Currently only enabled for built-in resources which are guaranteed to implement Protocol Buffers.
	// For custom resources, CRDs can not support Protocol Buffers but Aggregated API can.
	// See doc: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#advanced-features-and-flexibility
	if err := clientgoscheme.AddToScheme(protobufScheme); err != nil {
		panic(err)
	}
}

// AddToProtobufScheme add the given SchemeBuilder into protobufScheme, which should
// be additional types that do support protobuf.
func AddToProtobufScheme(addToScheme func(*runtime.Scheme) error) error {
	protobufSchemeLock.Lock()
	defer protobufSchemeLock.Unlock()
	return addToScheme(protobufScheme)
}

// IsObjectNamespaced returns true if the object is namespace scoped.
// For unstructured objects the gvk is found from the object itself.
func IsObjectNamespaced(obj runtime.Object, scheme *runtime.Scheme, restmapper meta.RESTMapper) (bool, error) {
	gvk, err := GVKForObject(obj, scheme)
	if err != nil {
		return false, err
	}

	return IsGVKNamespaced(gvk, restmapper)
}

// IsGVKNamespaced returns true if the object having the provided
// GVK is namespace scoped.
func IsGVKNamespaced(gvk schema.GroupVersionKind, restmapper meta.RESTMapper) (bool, error) {
	restmapping, err := restmapper.RESTMapping(schema.GroupKind{Group: gvk.Group, Kind: gvk.Kind})
	if err != nil {
		return false, fmt.Errorf("failed to get restmapping: %w", err)
	}

	scope := restmapping.Scope.Name()
	if scope == "" {
		return false, errors.New("scope cannot be identified, empty scope returned")
	}

	if scope != meta.RESTScopeNameRoot {
		return true, nil
	}
	return false, nil
}

// GVKForObject finds the GroupVersionKind associated with the given object, if there is only a single such GVK.
func GVKForObject(obj runtime.Object, scheme *runtime.Scheme) (schema.GroupVersionKind, error) {
	// TODO(directxman12): do we want to generalize this to arbitrary container types?
	// I think we'd need a generalized form of scheme or something.  It's a
	// shame there's not a reliable "GetGVK" interface that works by default
	// for unpopulated static types and populated "dynamic" types
	// (unstructured, partial, etc)

	// check for PartialObjectMetadata, which is analogous to unstructured, but isn't handled by ObjectKinds
	_, isPartial := obj.(*metav1.PartialObjectMetadata)
	_, isPartialList := obj.(*metav1.PartialObjectMetadataList)
	if isPartial || isPartialList {
		// we require that the GVK be populated in order to recognize the object
		gvk := obj.GetObjectKind().GroupVersionKind()
		if len(gvk.Kind) == 0 {
			return schema.GroupVersionKind{}, runtime.NewMissingKindErr("unstructured object has no kind")
		}
		if len(gvk.Version) == 0 {
			return schema.GroupVersionKind{}, runtime.NewMissingVersionErr("unstructured object has no version")
		}
		return gvk, nil
	}

	// Use the given scheme to retrieve all the GVKs for the object.
	gvks, isUnversioned, err := scheme.ObjectKinds(obj)
	if err != nil {
		return schema.GroupVersionKind{}, err
	}
	if isUnversioned {
		return schema.GroupVersionKind{}, fmt.Errorf("cannot create group-version-kind for unversioned type %T", obj)
	}

	switch {
	case len(gvks) < 1:
		// If the object has no GVK, the object might not have been registered with the scheme.
		// or it's not a valid object.
		return schema.GroupVersionKind{}, fmt.Errorf("no GroupVersionKind associated with Go type %T, was the type registered with the Scheme?", obj)
	case len(gvks) > 1:
		err := fmt.Errorf("multiple GroupVersionKinds associated with Go type %T within the Scheme, this can happen when a type is registered for multiple GVKs at the same time", obj)

		// We've found multiple GVKs for the object.
		currentGVK := obj.GetObjectKind().GroupVersionKind()
		if !currentGVK.Empty() {
			// If the base object has a GVK, check if it's in the list of GVKs before using it.
			for _, gvk := range gvks {
				if gvk == currentGVK {
					return gvk, nil
				}
			}

			return schema.GroupVersionKind{}, fmt.Errorf(
				"%w: the object's supplied GroupVersionKind %q was not found in the Scheme's list; refusing to guess at one: %q", err, currentGVK, gvks)
		}

		// This should only trigger for things like metav1.XYZ --
		// normal versioned types should be fine.
		//
		// See https://github.com/kubernetes-sigs/controller-runtime/issues/362
		// for more information.
		return schema.GroupVersionKind{}, fmt.Errorf(
			"%w: callers can either fix their type registration to only register it once, or specify the GroupVersionKind to use for object passed in; refusing to guess at one: %q", err, gvks)
	default:
		// In any other case, we've found a single GVK for the object.
		return gvks[0], nil
	}
}

// RESTClientForGVK constructs a new rest.Interface capable of accessing the resource associated
// with the given GroupVersionKind. The REST client will be configured to use the negotiated serializer from
// baseConfig, if set, otherwise a default serializer will be set.
func RESTClientForGVK(gvk schema.GroupVersionKind, isUnstructured bool, baseConfig *rest.Config, codecs serializer.CodecFactory, httpClient *http.Client) (rest.Interface, error) {
	if httpClient == nil {
		return nil, fmt.Errorf("httpClient must not be nil, consider using rest.HTTPClientFor(c) to create a client")
	}
	return rest.RESTClientForConfigAndClient(createRestConfig(gvk, isUnstructured, baseConfig, codecs), httpClient)
}

// createRestConfig copies the base config and updates needed fields for a new rest config.
func createRestConfig(gvk schema.GroupVersionKind, isUnstructured bool, baseConfig *rest.Config, codecs serializer.CodecFactory) *rest.Config {
	gv := gvk.GroupVersion()

	cfg := rest.CopyConfig(baseConfig)
	cfg.GroupVersion = &gv
	if gvk.Group == "" {
		cfg.APIPath = "/api"
	} else {
		cfg.APIPath = "/apis"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = rest.DefaultKubernetesUserAgent()
	}
	// TODO(FillZpp): In the long run, we want to check discovery or something to make sure that this is actually true.
	if cfg.ContentType == "" && !isUnstructured {
		protobufSchemeLock.RLock()
		if protobufScheme.Recognizes(gvk) {
			cfg.ContentType = runtime.ContentTypeProtobuf
		}
		protobufSchemeLock.RUnlock()
	}

	if isUnstructured {
		// If the object is unstructured, we use the client-go dynamic serializer.
		cfg = dynamic.ConfigFor(cfg)
	} else {
		cfg.NegotiatedSerializer = serializerWithTargetZeroingDecode{NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: codecs}}
	}

	return cfg
}

type serializerWithTargetZeroingDecode struct {
	runtime.NegotiatedSerializer
}

func (s serializerWithTargetZeroingDecode) DecoderToVersion(serializer runtime.Decoder, r runtime.GroupVersioner) runtime.Decoder {
	return targetZeroingDecoder{upstream: s.NegotiatedSerializer.DecoderToVersion(serializer, r)}
}

type targetZeroingDecoder struct {
	upstream runtime.Decoder
}

func (t targetZeroingDecoder) Decode(data []byte, defaults *schema.GroupVersionKind, into runtime.Object) (runtime.Object, *schema.GroupVersionKind, error) {
	zero(into)
	return t.upstream.Decode(data, defaults, into)
}

// zero zeros the value of a pointer.
func zero(x interface{}) {
	if x == nil {
		return
	}
	res := reflect.ValueOf(x).Elem()
	res.Set(reflect.Zero(res.Type()))
}
