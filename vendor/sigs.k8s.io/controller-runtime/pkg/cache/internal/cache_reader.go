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

package internal

import (
	"context"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/internal/field/selector"
)

// CacheReader is a client.Reader.
var _ client.Reader = &CacheReader{}

// CacheReader wraps a cache.Index to implement the client.CacheReader interface for a single type.
type CacheReader struct {
	// indexer is the underlying indexer wrapped by this cache.
	indexer cache.Indexer

	// groupVersionKind is the group-version-kind of the resource.
	groupVersionKind schema.GroupVersionKind

	// scopeName is the scope of the resource (namespaced or cluster-scoped).
	scopeName apimeta.RESTScopeName

	// disableDeepCopy indicates not to deep copy objects during get or list objects.
	// Be very careful with this, when enabled you must DeepCopy any object before mutating it,
	// otherwise you will mutate the object in the cache.
	disableDeepCopy bool
}

// Get checks the indexer for the object and writes a copy of it if found.
func (c *CacheReader) Get(_ context.Context, key client.ObjectKey, out client.Object, _ ...client.GetOption) error {
	if c.scopeName == apimeta.RESTScopeNameRoot {
		key.Namespace = ""
	}
	storeKey := objectKeyToStoreKey(key)

	// Lookup the object from the indexer cache
	obj, exists, err := c.indexer.GetByKey(storeKey)
	if err != nil {
		return err
	}

	// Not found, return an error
	if !exists {
		return apierrors.NewNotFound(schema.GroupResource{
			Group: c.groupVersionKind.Group,
			// Resource gets set as Kind in the error so this is fine
			Resource: c.groupVersionKind.Kind,
		}, key.Name)
	}

	// Verify the result is a runtime.Object
	if _, isObj := obj.(runtime.Object); !isObj {
		// This should never happen
		return fmt.Errorf("cache contained %T, which is not an Object", obj)
	}

	if c.disableDeepCopy {
		// skip deep copy which might be unsafe
		// you must DeepCopy any object before mutating it outside
	} else {
		// deep copy to avoid mutating cache
		obj = obj.(runtime.Object).DeepCopyObject()
	}

	// Copy the value of the item in the cache to the returned value
	// TODO(directxman12): this is a terrible hack, pls fix (we should have deepcopyinto)
	outVal := reflect.ValueOf(out)
	objVal := reflect.ValueOf(obj)
	if !objVal.Type().AssignableTo(outVal.Type()) {
		return fmt.Errorf("cache had type %s, but %s was asked for", objVal.Type(), outVal.Type())
	}
	reflect.Indirect(outVal).Set(reflect.Indirect(objVal))
	if !c.disableDeepCopy {
		out.GetObjectKind().SetGroupVersionKind(c.groupVersionKind)
	}

	return nil
}

// List lists items out of the indexer and writes them to out.
func (c *CacheReader) List(_ context.Context, out client.ObjectList, opts ...client.ListOption) error {
	var objs []interface{}
	var err error

	listOpts := client.ListOptions{}
	listOpts.ApplyOptions(opts)

	if listOpts.Continue != "" {
		return fmt.Errorf("continue list option is not supported by the cache")
	}

	switch {
	case listOpts.FieldSelector != nil:
		requiresExact := selector.RequiresExactMatch(listOpts.FieldSelector)
		if !requiresExact {
			return fmt.Errorf("non-exact field matches are not supported by the cache")
		}
		// list all objects by the field selector. If this is namespaced and we have one, ask for the
		// namespaced index key. Otherwise, ask for the non-namespaced variant by using the fake "all namespaces"
		// namespace.
		objs, err = byIndexes(c.indexer, listOpts.FieldSelector.Requirements(), listOpts.Namespace)
	case listOpts.Namespace != "":
		objs, err = c.indexer.ByIndex(cache.NamespaceIndex, listOpts.Namespace)
	default:
		objs = c.indexer.List()
	}
	if err != nil {
		return err
	}
	var labelSel labels.Selector
	if listOpts.LabelSelector != nil {
		labelSel = listOpts.LabelSelector
	}

	limitSet := listOpts.Limit > 0

	runtimeObjs := make([]runtime.Object, 0, len(objs))
	for _, item := range objs {
		// if the Limit option is set and the number of items
		// listed exceeds this limit, then stop reading.
		if limitSet && int64(len(runtimeObjs)) >= listOpts.Limit {
			break
		}
		obj, isObj := item.(runtime.Object)
		if !isObj {
			return fmt.Errorf("cache contained %T, which is not an Object", item)
		}
		meta, err := apimeta.Accessor(obj)
		if err != nil {
			return err
		}
		if labelSel != nil {
			lbls := labels.Set(meta.GetLabels())
			if !labelSel.Matches(lbls) {
				continue
			}
		}

		var outObj runtime.Object
		if c.disableDeepCopy || (listOpts.UnsafeDisableDeepCopy != nil && *listOpts.UnsafeDisableDeepCopy) {
			// skip deep copy which might be unsafe
			// you must DeepCopy any object before mutating it outside
			outObj = obj
		} else {
			outObj = obj.DeepCopyObject()
			outObj.GetObjectKind().SetGroupVersionKind(c.groupVersionKind)
		}
		runtimeObjs = append(runtimeObjs, outObj)
	}
	return apimeta.SetList(out, runtimeObjs)
}

func byIndexes(indexer cache.Indexer, requires fields.Requirements, namespace string) ([]interface{}, error) {
	var (
		err  error
		objs []interface{}
		vals []string
	)
	indexers := indexer.GetIndexers()
	for idx, req := range requires {
		indexName := FieldIndexName(req.Field)
		indexedValue := KeyToNamespacedKey(namespace, req.Value)
		if idx == 0 {
			// we use first require to get snapshot data
			// TODO(halfcrazy): use complicated index when client-go provides byIndexes
			// https://github.com/kubernetes/kubernetes/issues/109329
			objs, err = indexer.ByIndex(indexName, indexedValue)
			if err != nil {
				return nil, err
			}
			if len(objs) == 0 {
				return nil, nil
			}
			continue
		}
		fn, exist := indexers[indexName]
		if !exist {
			return nil, fmt.Errorf("index with name %s does not exist", indexName)
		}
		filteredObjects := make([]interface{}, 0, len(objs))
		for _, obj := range objs {
			vals, err = fn(obj)
			if err != nil {
				return nil, err
			}
			for _, val := range vals {
				if val == indexedValue {
					filteredObjects = append(filteredObjects, obj)
					break
				}
			}
		}
		if len(filteredObjects) == 0 {
			return nil, nil
		}
		objs = filteredObjects
	}
	return objs, nil
}

// objectKeyToStorageKey converts an object key to store key.
// It's akin to MetaNamespaceKeyFunc. It's separate from
// String to allow keeping the key format easily in sync with
// MetaNamespaceKeyFunc.
func objectKeyToStoreKey(k client.ObjectKey) string {
	if k.Namespace == "" {
		return k.Name
	}
	return k.Namespace + "/" + k.Name
}

// FieldIndexName constructs the name of the index over the given field,
// for use with an indexer.
func FieldIndexName(field string) string {
	return "field:" + field
}

// allNamespacesNamespace is used as the "namespace" when we want to list across all namespaces.
const allNamespacesNamespace = "__all_namespaces"

// KeyToNamespacedKey prefixes the given index key with a namespace
// for use in field selector indexes.
func KeyToNamespacedKey(ns string, baseKey string) string {
	if ns != "" {
		return ns + "/" + baseKey
	}
	return allNamespacesNamespace + "/" + baseKey
}
