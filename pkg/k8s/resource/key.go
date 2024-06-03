// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"
)

// Key of an K8s object, e.g. name and optional namespace.
type Key = cache.ObjectName

func NewKey(obj any) Key {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		namespace, name, _ := cache.SplitMetaNamespaceKey(d.Key)
		return Key{Name: name, Namespace: namespace}
	}

	meta, err := meta.Accessor(obj)
	if err != nil {
		return Key{}
	}
	if len(meta.GetNamespace()) > 0 {
		return Key{Name: meta.GetName(), Namespace: meta.GetNamespace()}
	}
	return Key{Name: meta.GetName()}
}
