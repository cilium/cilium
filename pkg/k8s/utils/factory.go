// Copyright 2018 Authors of Cilium
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

package utils

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/serializer"
	"github.com/cilium/cilium/pkg/versioned"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

var (
	// k8sSyncCM has all controllers that are in charge of syncing up the
	// watched objects with Kubernetes API-server.
	k8sSyncCM = controller.NewManager()

	// listers maps an interface to a lister.
	listers = map[reflect.Type]lister{}
	// equals maps an interface to an equal function.
	equals = map[reflect.Type]versioned.DeepEqualFunc{}
	// casts maps an interface to a castToDeepCopy function.
	casts = map[reflect.Type]castToDeepCopy{}
	// resourcers maps an interface to a resource name (string).
	resourcers = map[reflect.Type]string{}
)

// castToDeepCopy returns the interface passed deep copied into its own object.
type castToDeepCopy func(i interface{}) meta_v1.Object

// lister returns a function that, when called, returns a versioned.Map
// of all objects the lister function can retrieve.
type lister func(client interface{}) func() (versioned.Map, error)

// ControllerSyncer implements the cache.Controller interface, in particular
// the HasSynced method with the help of our own ResourceEventHandler
// implementation.
type ControllerSyncer struct {
	Controller           cache.Controller
	ResourceEventHandler ResourceEventHandler
}

// Run starts the controller, which will be stopped when stopCh is closed.
func (c *ControllerSyncer) Run(stopCh <-chan struct{}) {
	c.Controller.Run(stopCh)
}

// HasSynced returns true if the controller has synced and the resource event
// handler has handled all requests.
func (c *ControllerSyncer) HasSynced() bool {
	return c.ResourceEventHandler.HasSynced()
}

// LastSyncResourceVersion is the resource version observed when last synced
// with the underlying store.
func (c *ControllerSyncer) LastSyncResourceVersion() string {
	return c.Controller.LastSyncResourceVersion()
}

// ResourceEventHandler is a wrapper for the cache.ResourceEventHandler
// interface with the addition of the HasSynced() bool method which allows
// the caller to know if all events were processed by the ResourceEventHandler.
type ResourceEventHandler interface {
	cache.ResourceEventHandler
	HasSynced() bool
}

// ResourceEventHandlerSyncer implements the ResourceEventHandler
type ResourceEventHandlerSyncer struct {
	// reh is the cache.ResourceEventHandler underlying implementation.
	reh cache.ResourceEventHandler
	// hasSynced is closed when all the elements synced with Kubernetes are
	// processed.
	hasSynced chan struct{}
	// fqueue is the queue that serializes all incoming requests.
	fqueue *serializer.FunctionQueue
}

// OnAdd is the function called when an addition event is received.
func (rehs *ResourceEventHandlerSyncer) OnAdd(obj interface{}) {
	rehs.reh.OnAdd(obj)
}

// OnUpdate is the function called when an update event is received.
func (rehs *ResourceEventHandlerSyncer) OnUpdate(oldObj, newObj interface{}) {
	rehs.reh.OnUpdate(oldObj, newObj)
}

// OnDelete is the function called when an delete event is received.
func (rehs *ResourceEventHandlerSyncer) OnDelete(obj interface{}) {
	rehs.reh.OnDelete(obj)
}

// HasSynced returns true if all the events received from kubernetes are
// processed by the serializer queue.
func (rehs *ResourceEventHandlerSyncer) HasSynced() bool {
	select {
	case <-rehs.hasSynced:
		return true
	default:
		return false
	}
}

// RegisterObject registers the given resourceObj with the given resourceName,
// castToDeepCopy, lister and equal Functions.
// Parameters:
//  * resourceObj: the interface type that is going to be registered.
//  * resourceName: the resource name registered in Kubernetes API-Server.
//  * castFunc: the castToDeepCopy function that will do a deep copy of
// 	  resourceObj when called.
//  * listerFunc: the lister function that will return list of resourceObj when
// 	  called.
//  * equalFunc: the equal function that will return true if 2 resourceObj are
//    considered the same by the equalFunc.
func RegisterObject(
	resourceObj interface{},
	resourceName string,
	castFunc castToDeepCopy,
	listerFunc lister,
	equalFunc versioned.DeepEqualFunc,
) {
	typeOfObj := reflect.TypeOf(resourceObj)

	if v, ok := resourcers[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	resourcers[typeOfObj] = resourceName

	if v, ok := casts[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	casts[typeOfObj] = castFunc

	if v, ok := listers[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	listers[typeOfObj] = listerFunc

	if v, ok := equals[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	equals[typeOfObj] = equalFunc
}

// ControllerFactory returns a kubernetes controller.
// Parameters:
//  * k8sGetter is the client used to watch for kubernetes events.
//  * resourceObj: is an object of the type that you expect to receive.
//  * rehf: is the  resource event handler funcs that is used to handle the
//    stream events.
//  * selector: field selector for the watch created, if nil all fields are
//    selected.
func ControllerFactory(
	k8sGetter cache.Getter,
	resourceObj runtime.Object,
	rehf ResourceEventHandler,
	selector fields.Selector,
) cache.Controller {

	if selector == nil {
		selector = fields.Everything()
	}

	_, c := cache.NewInformer(
		cache.NewListWatchFromClient(
			k8sGetter,
			resourceNameOf(resourceObj),
			v1.NamespaceAll,
			selector,
		),
		resourceObj,
		0,
		rehf,
	)

	// Wrap the controller from Kubernetes so we can actually know when all
	// objects were synchronized and processed from kubernetes.
	return &ControllerSyncer{Controller: c, ResourceEventHandler: rehf}
}

// ResourceEventHandlerFactory returns a ResourceEventHandlerSyncer,
// the resource event handler will have a serializer.FunctionQueue to enqueue
// the received events.
// Parameters:
//  * addFunc: function serialized in the queue when an object addition is
//    received.
//  * delFunc: function serialized in the queue when an object deletion is
//    received.
//  * updateFunc function serialized in the queue when an object update
//    is received.
//  * missingFunc will return a versioned.Map for the objects that are
//    considered missing from the versioned.Map provided.
//  * resourceObj: object of the type the caller is expected to the resource
//    event handler to receive.
//  * listerClient will be the client used to fetch the k8s data from
//    kube-apiserver for the resourceObj provided.
//  * reSyncPeriod: if non-zero, will re-list this often (you will get OnUpdate
//    calls, even if nothing changed). Otherwise, re-list will be delayed as
//    long as possible (until the upstream source closes the watch or times out,
//    or you stop the controller).
//  * gauge: prometheus gauge that is set whenever an event (add/del/update) is
//    received by the watcher.
func ResourceEventHandlerFactory(
	addFunc, delFunc func(i interface{}) func() error,
	updateFunc func(old, new interface{}) func() error,
	missingFunc func(comparableMap versioned.Map) versioned.Map,
	resourceObj runtime.Object,
	listerClient interface{},
	reSyncPeriod time.Duration,
	gauge prometheus.Gauge,
) ResourceEventHandler {

	fqueue := serializer.NewFunctionQueue(1024)
	castToDeepCopy := castFuncFactory(resourceObj)
	rehf := &cache.ResourceEventHandlerFuncs{}
	scm := versioned.NewSyncComparableMap(equalFuncFactory(resourceObj))

	rehs := &ResourceEventHandlerSyncer{
		reh:       rehf,
		hasSynced: make(chan struct{}),
	}

	if addFunc != nil && delFunc != nil {
		replaceFunc := replaceFuncFactory(listerClient, resourceObj, addFunc,
			delFunc, updateFunc, missingFunc, fqueue)
		s := sync.Once{}

		k8sSyncCM.UpdateController(fmt.Sprintf("k8s-sync-%s", resourceNameOf(resourceObj)),
			controller.ControllerParams{
				DoFunc: func() error {
					err := scm.Replace(replaceFunc)
					if err == nil {
						s.Do(func() {
							// Close the hasSynced channel to signalize the that
							// all other functions queued were serialized. This
							// will make sure the all events received after the
							// cache was synced were processed by the queue.
							fqueue.Enqueue(func() error {
								close(rehs.hasSynced)
								return nil
							}, serializer.NoRetry)
						})
					}

					return err
				},
				RunInterval: reSyncPeriod,
			})
	}

	if addFunc != nil {
		rehf.AddFunc = func(obj interface{}) {
			gauge.SetToCurrentTime()
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				if scm.AddEqual(GetVerStructFrom(metaObj)) {
					return
				}
				fqueue.Enqueue(addFunc(metaObj), serializer.NoRetry)
			}
		}
	}
	if updateFunc != nil {
		rehf.UpdateFunc = func(oldObj, newObj interface{}) {
			gauge.SetToCurrentTime()
			if oldMetaObj := castToDeepCopy(oldObj); oldMetaObj != nil {
				if newMetaObj := castToDeepCopy(newObj); newMetaObj != nil {
					if scm.AddEqual(GetVerStructFrom(newMetaObj)) {
						return
					}
					fqueue.Enqueue(updateFunc(oldMetaObj, newMetaObj), serializer.NoRetry)
				}
			}
		}
	}

	if delFunc != nil {
		rehf.DeleteFunc = func(obj interface{}) {
			gauge.SetToCurrentTime()
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				if ok := scm.Delete(versioned.UUID(GetObjUID(metaObj))); !ok {
					return
				}
				fqueue.Enqueue(delFunc(metaObj), serializer.NoRetry)
			}
		}
	}

	return rehs
}
func listerFactory(client, i interface{}) func() (versioned.Map, error) {
	lister, ok := listers[reflect.TypeOf(i)]
	if !ok {
		panic(fmt.Sprintf("Object type '%s' not registered", reflect.TypeOf(i)))
	}
	return lister(client)
}

func resourceNameOf(i interface{}) string {
	resourceName, ok := resourcers[reflect.TypeOf(i)]
	if !ok {
		panic(fmt.Sprintf("Object type '%s' not registered", reflect.TypeOf(i)))
	}
	return resourceName
}

func castFuncFactory(i interface{}) func(i interface{}) meta_v1.Object {
	castFunc, ok := casts[reflect.TypeOf(i)]
	if !ok {
		panic(fmt.Sprintf("Object type '%s' not registered", reflect.TypeOf(i)))
	}
	return castFunc
}

func equalFuncFactory(i interface{}) versioned.DeepEqualFunc {
	equalFunc, ok := equals[reflect.TypeOf(i)]
	if !ok {
		panic(fmt.Sprintf("Object type '%s' not registered", reflect.TypeOf(i)))
	}
	return equalFunc
}

func replaceFuncFactory(
	listerClient interface{},
	resourceObj runtime.Object,
	addFunc, delFunc func(i interface{}) func() error,
	updateFunc func(old, new interface{}) func() error,
	missingFunc func(comparableMap versioned.Map) versioned.Map,
	fqueue *serializer.FunctionQueue,
) func(oldMap *versioned.ComparableMap) (*versioned.ComparableMap, error) {

	lister := listerFactory(listerClient, resourceObj)

	return func(oldCompMapCpy *versioned.ComparableMap) (*versioned.ComparableMap, error) {
		// retrieve all new elements from the lister()
		newMap, err := lister()
		if err != nil {
			return nil, err
		}
		var (
			added       = versioned.NewMap()
			deleted     = versioned.NewMap()
			updatedOld  = versioned.NewMap()
			updatedNew  = versioned.NewMap()
			newEqualMap = &versioned.ComparableMap{
				Map:        newMap,
				DeepEquals: oldCompMapCpy.DeepEquals,
			}
		)

		// when should an object be deleted?
		// - when the object exists in the oldMap but no longer exists in the
		//   new map.
		for k, v := range oldCompMapCpy.Map {
			_, ok := newEqualMap.Get(k)
			if !ok {
				deleted.Add(k, v)
			}
		}

		// when should an object be added?
		// - when an object does not exists in the oldMap or, if exists, it's
		//   older and different than the one from kubernetes.
		for k, v := range newEqualMap.Map {
			oldObj, ok := oldCompMapCpy.Get(k)
			if ok {
				if oldObj.CompareVersion(v) < 0 &&
					!newEqualMap.DeepEquals(oldObj.Data, v.Data) {
					updatedOld.Add(k, oldObj)
					updatedNew.Add(k, v)
				}
			} else {
				added.Add(k, v)
			}
		}

		// when should we keep and updated version without performing any
		// operation?
		// - when an object is not going to be deleted and is stored locally
		//   with a newer version than the one retrieved from kubernetes.
		for k, v := range oldCompMapCpy.Map {
			_, exists := deleted.Get(k)
			if !exists {
				newEqualMap.AddEqual(k, v)
			}
		}

		if missingFunc != nil {
			// when should an object be added?
			// - when an object is missing locally regardless of the version
			missing := missingFunc(newEqualMap.Map)
			for k, newVS := range missing {
				added.Add(k, newVS)
			}
		}

		for k, v := range updatedNew {
			// If the objects to be updated exist in the added map, then
			// we will remove it from the added map as we will consider this an
			// update.
			added.Delete(k)
			oldObj, _ := updatedOld.Get(k)
			fqueue.Enqueue(updateFunc(oldObj.Data, v.Data), serializer.NoRetry)
		}
		for _, v := range added {
			fqueue.Enqueue(addFunc(v.Data), serializer.NoRetry)
		}
		for _, v := range deleted {
			fqueue.Enqueue(delFunc(v.Data), serializer.NoRetry)
		}

		return newEqualMap, nil
	}
}
