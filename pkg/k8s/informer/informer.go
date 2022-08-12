// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package informer

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	utilRuntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s")

func init() {
	utilRuntime.PanicHandlers = append(
		utilRuntime.PanicHandlers,
		func(r interface{}) {
			// from k8s library
			if err, ok := r.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				// honor the http.ErrAbortHandler sentinel panic value:
				//   ErrAbortHandler is a sentinel panic value to abort a handler.
				//   While any panic from ServeHTTP aborts the response to the client,
				//   panicking with ErrAbortHandler also suppresses logging of a stack trace to the server's error log.
				return
			}
			log.Fatal("Panic in Kubernetes runtime handler")
		},
	)
}

type ConvertFunc func(obj interface{}) interface{}

// NewInformer is a copy of k8s.io/client-go/tools/cache/NewInformer with a new
// argument which converts an object into another object that can be stored in
// the local cache.
func NewInformer(
	lw cache.ListerWatcher,
	objType k8sRuntime.Object,
	resyncPeriod time.Duration,
	h cache.ResourceEventHandler,
	convertFunc ConvertFunc,
) (cache.Store, cache.Controller) {
	// This will hold the client state, as we know it.
	clientState := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	return clientState, NewInformerWithStore(lw, objType, resyncPeriod, h, convertFunc, clientState)
}

// NewIndexerInformer is a copy of k8s.io/client-go/tools/cache/NewIndexerInformer with a new
// argument which converts an object into another object that can be stored in
// the local cache.
func NewIndexerInformer(
	lw cache.ListerWatcher,
	objType k8sRuntime.Object,
	resyncPeriod time.Duration,
	h cache.ResourceEventHandler,
	convertFunc ConvertFunc,
	indexers cache.Indexers,
) (cache.Indexer, cache.Controller) {
	clientState := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, indexers)
	return clientState, NewInformerWithStore(lw, objType, resyncPeriod, h, convertFunc, clientState)
}

// NewInformerWithStore uses the same arguments as NewInformer for which a
// caller can also set a cache.Store.
func NewInformerWithStore(
	lw cache.ListerWatcher,
	objType k8sRuntime.Object,
	resyncPeriod time.Duration,
	h cache.ResourceEventHandler,
	convertFunc ConvertFunc,
	clientState cache.Store,
) cache.Controller {

	// This will hold incoming changes. Note how we pass clientState in as a
	// KeyLister, that way resync operations will result in the correct set
	// of update/delete deltas.
	fifo := cache.NewDeltaFIFO(cache.MetaNamespaceKeyFunc, clientState)

	cacheMutationDetector := cache.NewCacheMutationDetector(fmt.Sprintf("%T", objType))

	cfg := &cache.Config{
		Queue:            fifo,
		ListerWatcher:    lw,
		ObjectType:       objType,
		FullResyncPeriod: resyncPeriod,
		RetryOnError:     false,

		Process: func(obj interface{}) error {
			// from oldest to newest
			for _, d := range obj.(cache.Deltas) {

				var obj interface{}
				if convertFunc != nil {
					obj = convertFunc(d.Object)
				} else {
					obj = d.Object
				}

				// In CI we detect if the objects were modified and panic
				// this is a no-op in production environments.
				cacheMutationDetector.AddObject(obj)

				switch d.Type {
				case cache.Sync, cache.Added, cache.Updated:
					if old, exists, err := clientState.Get(obj); err == nil && exists {
						if err := clientState.Update(obj); err != nil {
							return err
						}
						h.OnUpdate(old, obj)
					} else {
						if err := clientState.Add(obj); err != nil {
							return err
						}
						h.OnAdd(obj)
					}
				case cache.Deleted:
					if err := clientState.Delete(obj); err != nil {
						return err
					}
					h.OnDelete(obj)
				}
			}
			return nil
		},
	}
	return cache.New(cfg)
}
