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
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "k8s")

	// k8sSyncCM has all controllers that are in charge of syncing up the
	// watched objects with Kubernetes API-server.
	k8sSyncCM = controller.NewManager()

	// listers maps an interface to a lister.
	listers = map[interface{}]lister{}
	// casts maps an interface to a castToDeepCopy function.
	casts = map[interface{}]castToDeepCopy{}
	// equals maps an interface to an equal function.
	equals = map[interface{}]equal{}
	// resourcers maps an interface to a resource name (string).
	resourcers = map[interface{}]string{}
)

// castToDeepCopy returns the interface passed deep copied into its own object.
type castToDeepCopy func(i interface{}) meta_v1.Object

// lister returns a function that, when called, returns a versioned.Map
// of all objects the lister function can retrieve.
type lister func(client interface{}) func() (versioned.Map, error)

// equal returns either if both interfaces are considered equal or not.
type equal func(o1, o2 interface{}) bool

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
	equalFunc equal,
) {
	typeOfObj := reflect.TypeOf(resourceObj)

	if v, ok := resourcers[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	resourcers[typeOfObj] = resourceName

	if v, ok := listers[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	listers[typeOfObj] = listerFunc

	if v, ok := casts[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	casts[typeOfObj] = castFunc

	if v, ok := equals[typeOfObj]; ok {
		panic(fmt.Sprintf("Object '%s' already registered for the type '%s'", typeOfObj, reflect.TypeOf(v)))
	}
	equals[typeOfObj] = equalFunc
}

// ControllerFactory returns a kubernetes controller.
// Parameters:
//  * k8sGetter is the client used to watch for kubernetes events.
//  * resourceObj: is an object of the type that you expect to receive.
//  * resyncPeriod: if non-zero, will re-list this often (you will get OnUpdate
//    calls, even if nothing changed). Otherwise, re-list will be delayed as
//    long as possible (until the upstream source closes the watch or times out,
//    or you stop the controller).
//  * rehf: is the  resource event handler funcs that is used to handle the
//    stream events.
func ControllerFactory(
	k8sGetter cache.Getter,
	resourceObj runtime.Object,
	rehf cache.ResourceEventHandlerFuncs,
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

	return c
}

// ResourceEventHandlerFactory returns a kubernetes ResourceEventHandlerFuncs,
// the resource event handler will have a serializer.FunctionQueue to enqueue
// the received events.
// Parameters:
//  * addFunc is the function serialized in the queue when an object addition is
//    received.
//  * delFunc is the function serialized in the queue when an object deletion is
//    received.
//  * updateFunc is the function serialized in the queue when an object update
//    is received.
//  * resourceObj: is an object of the type that you expect to receive.
func ResourceEventHandlerFactory(
	addFunc, delFunc func(i interface{}) func() error,
	updateFunc func(old, new interface{}) func() error,
	missingFunc func(versioned.Map) versioned.Map,
	resourceObj runtime.Object,
	listerClient interface{},
	reSyncPeriod time.Duration,
	gauge prometheus.Gauge,
) cache.ResourceEventHandlerFuncs {

	fqueue := serializer.NewFunctionQueue(1024)
	castToDeepCopy := castFuncFactory(resourceObj)
	im := versioned.NewSyncMap(equalFuncFactory(resourceObj))

	if addFunc != nil && delFunc != nil {
		replaceFunc := replaceFuncFactory(listerClient, resourceObj, addFunc, delFunc, missingFunc, fqueue)
		k8sSyncCM.UpdateController(fmt.Sprintf("k8s-sync-%s", resourceNameOf(resourceObj)),
			controller.ControllerParams{
				DoFunc: func() error {
					return im.DoLocked(nil, replaceFunc)
				},
				RunInterval: reSyncPeriod,
			})
	}

	rehf := cache.ResourceEventHandlerFuncs{}
	if addFunc != nil {
		rehf.AddFunc = func(obj interface{}) {
			gauge.SetToCurrentTime()
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				log.Debugf("A1 Type Of: %s", reflect.TypeOf(metaObj))
				if im.AddEqual(getVerStructFrom(metaObj)) {
					return
				}
				log.Debugf("It passed")
				fqueue.Enqueue(addFunc(metaObj), serializer.NoRetry)
			}
		}
	}
	if updateFunc != nil {
		rehf.UpdateFunc = func(oldObj, newObj interface{}) {
			gauge.SetToCurrentTime()
			if oldMetaObj := castToDeepCopy(oldObj); oldMetaObj != nil {
				if newMetaObj := castToDeepCopy(newObj); newMetaObj != nil {
					log.Debugf("U1 Type Of: %s", reflect.TypeOf(oldMetaObj))
					log.Debugf("U1 Type Of: %s", reflect.TypeOf(newMetaObj))
					if im.AddEqual(getVerStructFrom(newMetaObj)) {
						return
					}
					log.Debugf("It passed")
					fqueue.Enqueue(updateFunc(oldMetaObj, newMetaObj), serializer.NoRetry)
				}
			}
		}
	}

	if delFunc != nil {
		rehf.DeleteFunc = func(obj interface{}) {
			gauge.SetToCurrentTime()
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				log.Debugf("D1 Type Of: %s", reflect.TypeOf(metaObj))
				if ok := im.Delete(versioned.UUID(GetObjUID(metaObj))); !ok {
					return
				}
				log.Debugf("It passed")
				fqueue.Enqueue(delFunc(metaObj), serializer.NoRetry)
			}
		}
	}

	return rehf
}

func getVerStructFrom(objMeta meta_v1.Object) (versioned.UUID, versioned.Object) {
	uuid := versioned.UUID(GetObjUID(objMeta))
	v := versioned.ParseVersion(objMeta.GetResourceVersion())
	vs := versioned.Object{
		Data:    objMeta,
		Version: v,
	}
	return uuid, vs
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

func equalFuncFactory(i interface{}) func(o1, o2 interface{}) bool {
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
	missingFunc func(versioned.Map) versioned.Map,
	fqueue *serializer.FunctionQueue,
) func(oldMap *versioned.EqualsMap) (*versioned.EqualsMap, error) {

	lister := listerFactory(listerClient, resourceObj)

	return func(oldMap *versioned.EqualsMap) (*versioned.EqualsMap, error) {
		newMap, err := lister()
		if err != nil {
			return nil, err
		}
		var (
			added       = versioned.Map{}
			deleted     = versioned.Map{}
			newEqualMap = &versioned.EqualsMap{
				Map: newMap,
				E:   oldMap.E,
			}
		)
		for k, oldVS := range oldMap.Map {
			newVS, ok := newMap.Get(k)
			if ok {
				if !newEqualMap.AddEqual(k, oldVS) {
					added.Add(k, newVS)
				}
			} else {
				deleted.Add(k, oldVS)
			}
		}

		if missingFunc != nil {
			missing := missingFunc(newMap)
			for k, newVS := range missing {
				added.Add(k, newVS)
			}
		}

		for k, newVS := range newMap {
			_, ok := oldMap.Get(k)
			if !ok {
				added.Add(k, newVS)
			}
		}

		for _, v := range added {
			log.Debugf("A11 Type Of: %s", reflect.TypeOf(v.Data))
			fqueue.Enqueue(addFunc(v.Data), serializer.NoRetry)
			log.Debugf("It passed")
		}
		for _, v := range deleted {
			log.Debugf("D11 Type Of: %s", reflect.TypeOf(v.Data))
			fqueue.Enqueue(delFunc(v.Data), serializer.NoRetry)
			log.Debugf("It passed")
		}

		return newEqualMap, nil
	}
}
