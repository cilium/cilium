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

package client

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// clientRestResources creates and stores rest clients and metadata for Kubernetes types.
type clientRestResources struct {
	// httpClient is the http client to use for requests
	httpClient *http.Client

	// config is the rest.Config to talk to an apiserver
	config *rest.Config

	// scheme maps go structs to GroupVersionKinds
	scheme *runtime.Scheme

	// mapper maps GroupVersionKinds to Resources
	mapper meta.RESTMapper

	// codecs are used to create a REST client for a gvk
	codecs serializer.CodecFactory

	// structuredResourceByType stores structured type metadata
	structuredResourceByType map[schema.GroupVersionKind]*resourceMeta
	// unstructuredResourceByType stores unstructured type metadata
	unstructuredResourceByType map[schema.GroupVersionKind]*resourceMeta
	mu                         sync.RWMutex
}

// newResource maps obj to a Kubernetes Resource and constructs a client for that Resource.
// If the object is a list, the resource represents the item's type instead.
func (c *clientRestResources) newResource(gvk schema.GroupVersionKind,
	isList bool,
	forceDisableProtoBuf bool,
	isUnstructured bool,
) (*resourceMeta, error) {
	if strings.HasSuffix(gvk.Kind, "List") && isList {
		// if this was a list, treat it as a request for the item's resource
		gvk.Kind = gvk.Kind[:len(gvk.Kind)-4]
	}

	client, err := apiutil.RESTClientForGVK(gvk, forceDisableProtoBuf, isUnstructured, c.config, c.codecs, c.httpClient)
	if err != nil {
		return nil, err
	}
	mapping, err := c.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, err
	}
	return &resourceMeta{Interface: client, mapping: mapping, gvk: gvk}, nil
}

type applyConfiguration interface {
	GetName() *string
	GetNamespace() *string
	GetKind() *string
	GetAPIVersion() *string
}

// getResource returns the resource meta information for the given type of object.
// If the object is a list, the resource represents the item's type instead.
func (c *clientRestResources) getResource(obj any) (*resourceMeta, error) {
	var gvk schema.GroupVersionKind
	var err error
	var isApplyConfiguration bool
	switch o := obj.(type) {
	case runtime.Object:
		gvk, err = apiutil.GVKForObject(o, c.scheme)
		if err != nil {
			return nil, err
		}
	case runtime.ApplyConfiguration:
		ac, ok := o.(applyConfiguration)
		if !ok {
			return nil, fmt.Errorf("%T is a runtime.ApplyConfiguration but not an applyConfiguration", o)
		}
		gvk, err = gvkFromApplyConfiguration(ac)
		if err != nil {
			return nil, err
		}
		isApplyConfiguration = true
	default:
		return nil, fmt.Errorf("bug: %T is neither a runtime.Object nor a runtime.ApplyConfiguration", o)
	}

	_, isUnstructured := obj.(runtime.Unstructured)
	forceDisableProtoBuf := isUnstructured || isApplyConfiguration

	// It's better to do creation work twice than to not let multiple
	// people make requests at once
	c.mu.RLock()
	resourceByType := c.structuredResourceByType
	if isUnstructured {
		resourceByType = c.unstructuredResourceByType
	}
	r, known := resourceByType[gvk]
	c.mu.RUnlock()

	if known {
		return r, nil
	}

	var isList bool
	if runtimeObject, ok := obj.(runtime.Object); ok && meta.IsListType(runtimeObject) {
		isList = true
	}

	// Initialize a new Client
	c.mu.Lock()
	defer c.mu.Unlock()
	r, err = c.newResource(gvk, isList, forceDisableProtoBuf, isUnstructured)
	if err != nil {
		return nil, err
	}
	resourceByType[gvk] = r
	return r, err
}

// getObjMeta returns objMeta containing both type and object metadata and state.
func (c *clientRestResources) getObjMeta(obj any) (*objMeta, error) {
	r, err := c.getResource(obj)
	if err != nil {
		return nil, err
	}
	objMeta := &objMeta{resourceMeta: r}

	switch o := obj.(type) {
	case runtime.Object:
		m, err := meta.Accessor(obj)
		if err != nil {
			return nil, err
		}
		objMeta.namespace = m.GetNamespace()
		objMeta.name = m.GetName()
	case applyConfiguration:
		objMeta.namespace = ptr.Deref(o.GetNamespace(), "")
		objMeta.name = ptr.Deref(o.GetName(), "")
	default:
		return nil, fmt.Errorf("object %T is neither a runtime.Object nor a runtime.ApplyConfiguration", obj)
	}

	return objMeta, nil
}

// resourceMeta stores state for a Kubernetes type.
type resourceMeta struct {
	// client is the rest client used to talk to the apiserver
	rest.Interface
	// gvk is the GroupVersionKind of the resourceMeta
	gvk schema.GroupVersionKind
	// mapping is the rest mapping
	mapping *meta.RESTMapping
}

// isNamespaced returns true if the type is namespaced.
func (r *resourceMeta) isNamespaced() bool {
	return r.mapping.Scope.Name() != meta.RESTScopeNameRoot
}

// resource returns the resource name of the type.
func (r *resourceMeta) resource() string {
	return r.mapping.Resource.Resource
}

// objMeta stores type and object information about a Kubernetes type.
type objMeta struct {
	// resourceMeta contains type information for the object
	*resourceMeta

	namespace string
	name      string
}
