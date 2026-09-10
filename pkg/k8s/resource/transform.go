// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"k8s.io/client-go/tools/cache"
)

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
