// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"
)

// Key of an K8s object, e.g. name and optional namespace.
type Key struct {
	// Name is the name of the object
	Name string

	// Namespace is the namespace, or empty if object is not namespaced.
	Namespace string
}

func (k Key) String() string {
	if len(k.Namespace) > 0 {
		return k.Namespace + "/" + k.Name
	}
	return k.Name
}

func NewKey(obj any) Key {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		namespace, name, _ := cache.SplitMetaNamespaceKey(d.Key)
		return Key{name, namespace}
	}

	meta, err := meta.Accessor(obj)
	if err != nil {
		return Key{}
	}
	if len(meta.GetNamespace()) > 0 {
		return Key{meta.GetName(), meta.GetNamespace()}
	}
	return Key{meta.GetName(), ""}
}
