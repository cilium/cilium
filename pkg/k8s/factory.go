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

package k8s

import (
	"reflect"
	"time"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/serializer"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

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
	resyncPeriod time.Duration,
	rehf cache.ResourceEventHandlerFuncs,
) cache.Controller {

	_, controller := cache.NewInformer(
		cache.NewListWatchFromClient(
			k8sGetter,
			resourceNameOf(resourceObj),
			v1.NamespaceAll,
			fields.Everything(),
		),
		resourceObj,
		resyncPeriod,
		rehf,
	)

	return controller
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
	resourceObj runtime.Object,
) cache.ResourceEventHandlerFuncs {

	fqueue := serializer.NewFunctionQueue(1024)
	castToDeepCopy := castFuncFactory(resourceObj)

	rehf := cache.ResourceEventHandlerFuncs{}
	if addFunc != nil {
		rehf.AddFunc = func(obj interface{}) {
			metrics.SetTSValue(metrics.EventTSK8s, time.Now())
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				fqueue.Enqueue(addFunc(metaObj), serializer.NoRetry)
			}
		}
	}
	if updateFunc != nil {
		rehf.UpdateFunc = func(oldObj, newObj interface{}) {
			metrics.SetTSValue(metrics.EventTSK8s, time.Now())
			if oldMetaObj := castToDeepCopy(oldObj); oldMetaObj != nil {
				if newMetaObj := castToDeepCopy(newObj); newMetaObj != nil {
					fqueue.Enqueue(updateFunc(oldMetaObj, newMetaObj), serializer.NoRetry)
				}
			}
		}
	}

	if delFunc != nil {
		rehf.DeleteFunc = func(obj interface{}) {
			metrics.SetTSValue(metrics.EventTSK8s, time.Now())
			if metaObj := castToDeepCopy(obj); metaObj != nil {
				fqueue.Enqueue(delFunc(metaObj), serializer.NoRetry)
			}
		}
	}

	return rehf
}

func resourceNameOf(i interface{}) string {
	switch i.(type) {
	case *networkingv1.NetworkPolicy:
		return "networkpolicies"
	case *v1.Service:
		return "services"
	case *v1.Endpoints:
		return "endpoints"
	case *v1beta1.Ingress:
		return "ingresses"
	case *cilium_v2.CiliumNetworkPolicy:
		return "ciliumnetworkpolicies"
	case *v1.Pod:
		return "pods"
	case *v1.Node:
		return "nodes"
	case *v1.Namespace:
		return "namespaces"
	default:
		log.Panicf("Invalid resource type %s", reflect.TypeOf(i))
		return ""
	}
}

func castFuncFactory(i interface{}) func(i interface{}) meta_v1.Object {
	switch i.(type) {
	case *networkingv1.NetworkPolicy:
		return copyObjToV1NetworkPolicy
	case *v1.Service:
		return copyObjToV1Services
	case *v1.Endpoints:
		return copyObjToV1Endpoints
	case *v1beta1.Ingress:
		return copyObjToV1beta1Ingress
	case *cilium_v2.CiliumNetworkPolicy:
		return copyObjToV2CNP
	case *v1.Pod:
		return copyObjToV1Pod
	case *v1.Node:
		return copyObjToV1Node
	case *v1.Namespace:
		return copyObjToV1Namespace
	default:
		log.Panicf("Invalid resource type %s", reflect.TypeOf(i))
		return nil
	}
}

func copyObjToV1NetworkPolicy(obj interface{}) meta_v1.Object {
	k8sNP, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 NetworkPolicy")
		return nil
	}
	return k8sNP.DeepCopy()
}

func copyObjToV1Services(obj interface{}) meta_v1.Object {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Service")
		return nil
	}
	return svc.DeepCopy()
}

func copyObjToV1Endpoints(obj interface{}) meta_v1.Object {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Endpoints")
		return nil
	}
	return ep.DeepCopy()
}

func copyObjToV1beta1Ingress(obj interface{}) meta_v1.Object {
	ing, ok := obj.(*v1beta1.Ingress)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1beta1 Ingress")
		return nil
	}
	return ing.DeepCopy()
}

func copyObjToV2CNP(obj interface{}) meta_v1.Object {
	cnp, ok := obj.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v2 CiliumNetworkPolicy")
		return nil
	}
	return cnp.DeepCopy()
}

func copyObjToV1Pod(obj interface{}) meta_v1.Object {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Pod")
		return nil
	}
	return pod.DeepCopy()
}

func copyObjToV1Node(obj interface{}) meta_v1.Object {
	node, ok := obj.(*v1.Node)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Node")
		return nil
	}
	return node.DeepCopy()
}

func copyObjToV1Namespace(obj interface{}) meta_v1.Object {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Namespace")
		return nil
	}
	return ns.DeepCopy()
}
