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
	"k8s.io/apimachinery/pkg/util/wait"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/serializer"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

var (
	// casts maps an interface to a castToDeepCopy function.
	casts = map[reflect.Type]castToDeepCopy{}
	// resourcers maps an interface to a resource name (string).
	resourcers = map[reflect.Type]string{}
)

// castToDeepCopy returns the interface passed deep copied into its own object.
type castToDeepCopy func(i interface{}) meta_v1.Object

// ControllerSyncer implements the cache.Controller interface, in particular
// the HasSynced method with the help of our own ResourceEventHandler
// implementation.
type ControllerSyncer struct {
	c   cache.Controller
	reh ResourceEventHandler
}

// Run starts the controller, which will be stopped when stopCh is closed.
func (c *ControllerSyncer) Run(stopCh <-chan struct{}) {
	c.c.Run(stopCh)
}

// HasSynced returns true if the controler has synced and the resource event
// handler has handled all requests.
func (c *ControllerSyncer) HasSynced() bool {
	return c.reh.HasSynced()
}

// LastSyncResourceVersion is the resource version observed when last synced
// with the underlying store.
func (c *ControllerSyncer) LastSyncResourceVersion() string {
	return c.c.LastSyncResourceVersion()
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
func RegisterObject(
	resourceObj interface{},
	resourceName string,
	castFunc castToDeepCopy,
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
}

// ControllerFactory returns a kubernetes controller.
// Parameters:
//  * k8sGetter is the client used to watch for kubernetes events.
//  * resourceObj: is an object of the type that you expect to receive.
//  * reSyncPeriod: if non-zero, will re-list this often (you will get OnUpdate
//    calls, even if nothing changed). Otherwise, re-list will be delayed as
//    long as possible (until the upstream source closes the watch or times out,
//    or you stop the controller).
//  * rehf: is the  resource event handler funcs that is used to handle the
//    stream events.
//  * selector: field selector for the watch created, if nil all fields are
//    selected.
func ControllerFactory(
	k8sGetter cache.Getter,
	resourceObj runtime.Object,
	reSyncPeriod time.Duration,
	rehf *ResourceEventHandlerSyncer,
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
		reSyncPeriod,
		rehf,
	)

	go func() {
		if ok := cache.WaitForCacheSync(wait.NeverStop, c.HasSynced); ok {
			// Enqueue the waitGroup.Done to signalize the that all other functions
			// queued were serialized. This will make sure the all events received
			// after the cached was synced were processed by the queue.
			rehf.fqueue.Enqueue(func() error {
				close(rehf.hasSynced)
				return nil
			}, serializer.NoRetry)
		}
	}()

	return c
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
//  * resourceObj: object of the type the caller is expected to the resource
//    event handler to receive.
//  * gauge: prometheus gauge that is set whenver an event (add/del/update) is
//    received by the watcher.
func ResourceEventHandlerFactory(
	addFunc, delFunc func(i interface{}) func() error,
	updateFunc func(old, new interface{}) func() error,
	resourceObj runtime.Object,
	gauge prometheus.Gauge,
) *ResourceEventHandlerSyncer {

	fqueue := serializer.NewFunctionQueue(1024)
	castToDeepCopy := castFuncFactory(resourceObj)
	rehf := &cache.ResourceEventHandlerFuncs{}

	rehs := &ResourceEventHandlerSyncer{
		reh:       rehf,
		hasSynced: make(chan struct{}),
		fqueue:    fqueue,
	}

	if addFunc != nil {
		rehf.AddFunc = func(obj interface{}) {
			gauge.SetToCurrentTime()
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				fqueue.Enqueue(addFunc(metaObj), serializer.NoRetry)
			}
		}
	}
	if updateFunc != nil {
		rehf.UpdateFunc = func(oldObj, newObj interface{}) {
			gauge.SetToCurrentTime()
			if oldMetaObj := castToDeepCopy(oldObj); oldMetaObj != nil {
				if newMetaObj := castToDeepCopy(newObj); newMetaObj != nil {
					fqueue.Enqueue(updateFunc(oldMetaObj, newMetaObj), serializer.NoRetry)
				}
			}
		}
	}

	if delFunc != nil {
		rehf.DeleteFunc = func(obj interface{}) {
			gauge.SetToCurrentTime()
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				fqueue.Enqueue(delFunc(metaObj), serializer.NoRetry)
			}
		}
	}

	return rehs
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
