// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package informer

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

type ConvertFunc func(obj interface{}) interface{}

// NewInformer is a copy of k8s.io/client-go/tools/cache/NewInformer with a new
// argument which converts an object into another object that can be stored in
// the local cache.
func NewInformer(
	lw cache.ListerWatcher,
	objType runtime.Object,
	resyncPeriod time.Duration,
	h cache.ResourceEventHandler,
	convertFunc ConvertFunc,
) (cache.Store, cache.Controller) {
	// This will hold the client state, as we know it.
	clientState := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	return clientState, NewInformerWithStore(lw, objType, resyncPeriod, h, convertFunc, clientState)
}

// NewInformerWithStore uses the same arguments as NewInformer for which a
// caller can also set a cache.Store.
func NewInformerWithStore(
	lw cache.ListerWatcher,
	objType runtime.Object,
	resyncPeriod time.Duration,
	h cache.ResourceEventHandler,
	convertFunc ConvertFunc,
	clientState cache.Store,
) cache.Controller {

	// This will hold incoming changes. Note how we pass clientState in as a
	// KeyLister, that way resync operations will result in the correct set
	// of update/delete deltas.
	fifo := cache.NewDeltaFIFO(cache.MetaNamespaceKeyFunc, clientState)

	cfg := &cache.Config{
		Queue:            fifo,
		ListerWatcher:    lw,
		ObjectType:       objType,
		FullResyncPeriod: resyncPeriod,
		RetryOnError:     false,

		Process: func(obj interface{}) error {
			// from oldest to newest
			for _, d := range obj.(cache.Deltas) {

				obj := convertFunc(d.Object)

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
