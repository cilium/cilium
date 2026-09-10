// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"fmt"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

// WithTransform sets the function to transform the object before storing it.
//
// The transform is only ever handed a freshly decoded object: the deletions
// which the informer reports as [cache.DeletedFinalStateUnknown] tombstones
// are stripped of their object rather than transformed, see transformDelta.
//
// The transform should not return an object holding a pointer into the one it
// is given, such as the address of one of its fields: that keeps the whole
// decoded object alive for as long as the store holds the transformed one,
// which is precisely what a transform is usually there to avoid.
func WithTransform[From, To k8sRuntime.Object](transform func(From) (To, error)) ResourceOption {
	return func(o *options) {
		o.sourceObj = func() k8sRuntime.Object {
			var obj From
			return obj
		}
		o.transform = func(fromRaw any) (any, error) {
			from, ok := fromRaw.(From)
			if !ok {
				var obj From
				return nil, fmt.Errorf("resource.WithTransform: expected %T, got %T", obj, fromRaw)
			}
			return transform(from)
		}
	}
}

// transformDelta applies the transform of the resource, if any, to the object
// of a single delta.
//
// A tombstone keeps its key and loses its object. Only the key is ever read,
// by NewKey and by the DeletionHandlingMetaNamespaceKeyFunc of the store, so
// there is nothing to transform, and the object is not one the transform may
// take for granted: DeltaFIFO.Replace takes it either from the store, in which
// case it has already been transformed and is still readable by the
// subscribers, or from a delta which is still queued for the same key, in
// which case it is a raw object which the very same batch is about to
// transform. It may also be nil, when the lookup in the store failed.
func transformDelta(transform cache.TransformFunc, obj any) (any, error) {
	if transform == nil {
		return obj, nil
	}
	if tombstone, isTombstone := obj.(cache.DeletedFinalStateUnknown); isTombstone {
		return cache.DeletedFinalStateUnknown{Key: tombstone.Key}, nil
	}
	return transform(obj)
}
