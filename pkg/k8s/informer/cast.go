// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package informer

import (
	"fmt"
	"log/slog"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CastInformerEvent tries to cast obj to type typ, directly
// or by DeletedFinalStateUnknown type. It returns nil and logs
// an error if obj doesn't contain type typ.
func CastInformerEvent[typ any](logger *slog.Logger, obj any) *typ {
	k8sObj, ok := obj.(*typ)
	if ok {
		return k8sObj
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		k8sObj, ok := deletedObj.Obj.(*typ)
		if ok {
			return k8sObj
		}
	}
	logger.Warn(
		fmt.Sprintf("Ignoring invalid type, expected: %T", new(typ)),
		logfields.Object, obj,
	)
	return nil
}
