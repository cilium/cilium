// Copyright 2018-2019 Authors of Cilium
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
	"net"
	"reflect"
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/comparator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
)

func CopyObjToV1NetworkPolicy(obj interface{}) *networkingv1.NetworkPolicy {
	k8sNP, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 NetworkPolicy")
		return nil
	}
	return k8sNP.DeepCopy()
}

func CopyObjToV1Services(obj interface{}) *v1.Service {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Service")
		return nil
	}
	return svc.DeepCopy()
}

func CopyObjToV1Endpoints(obj interface{}) *v1.Endpoints {
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Endpoints")
		return nil
	}
	return ep.DeepCopy()
}

func CopyObjToV1beta1Ingress(obj interface{}) *v1beta1.Ingress {
	ing, ok := obj.(*v1beta1.Ingress)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1beta1 Ingress")
		return nil
	}
	return ing.DeepCopy()
}

func CopyObjToV2CNP(obj interface{}) *cilium_v2.CiliumNetworkPolicy {
	cnp, ok := obj.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v2 CiliumNetworkPolicy")
		return nil
	}
	return cnp.DeepCopy()
}

func CopyObjToV1Pod(obj interface{}) *v1.Pod {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Pod")
		return nil
	}
	return pod.DeepCopy()
}

func CopyObjToV1Node(obj interface{}) *v1.Node {
	node, ok := obj.(*v1.Node)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Node")
		return nil
	}
	return node.DeepCopy()
}

func CopyObjToV1Namespace(obj interface{}) *v1.Namespace {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Namespace")
		return nil
	}
	return ns.DeepCopy()
}

func equalV1NetworkPolicy(o1, o2 interface{}) bool {
	np1, ok := o1.(*networkingv1.NetworkPolicy)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *networkingv1.NetworkPolicy", reflect.TypeOf(o1))
		return false
	}
	np2, ok := o2.(*networkingv1.NetworkPolicy)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *networkingv1.NetworkPolicy", reflect.TypeOf(o2))
		return false
	}
	// As Cilium uses all of the Spec from a NP it's not probably not worth
	// it to create a dedicated deep equal	 function to compare both network
	// policies.
	return np1.Name == np2.Name &&
		np1.Namespace == np2.Namespace &&
		reflect.DeepEqual(np1.Spec, np2.Spec)
}

func equalV1Services(o1, o2 interface{}) bool {
	svc1, ok := o1.(*v1.Service)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Service", reflect.TypeOf(o1))
		return false
	}
	svc2, ok := o2.(*v1.Service)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Service", reflect.TypeOf(o2))
		return false
	}

	// Service annotations are used to mark services as global, shared, etc.
	if !comparator.MapStringEquals(svc1.GetAnnotations(), svc2.GetAnnotations()) {
		return false
	}

	clusterIP := net.ParseIP(svc1.Spec.ClusterIP)
	headless := false
	if strings.ToLower(svc1.Spec.ClusterIP) == "none" {
		headless = true
	}
	si1 := NewService(clusterIP, headless, svc1.Labels, svc1.Spec.Selector)

	clusterIP = net.ParseIP(svc2.Spec.ClusterIP)
	headless = false
	if strings.ToLower(svc2.Spec.ClusterIP) == "none" {
		headless = true
	}
	si2 := NewService(clusterIP, headless, svc2.Labels, svc2.Spec.Selector)

	// Please write all the equalness logic inside the K8sServiceInfo.Equals()
	// method.
	return si1.DeepEquals(si2)
}

func equalV1Endpoints(o1, o2 interface{}) bool {
	ep1, ok := o1.(*v1.Endpoints)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Endpoints", reflect.TypeOf(o1))
		return false
	}
	ep2, ok := o2.(*v1.Endpoints)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Endpoints", reflect.TypeOf(o2))
		return false
	}
	// We only care about the Name, Namespace and Subsets of a particular
	// endpoint.
	return ep1.Name == ep2.Name &&
		ep1.Namespace == ep2.Namespace &&
		reflect.DeepEqual(ep1.Subsets, ep2.Subsets)
}

func equalV1beta1Ingress(o1, o2 interface{}) bool {
	ing1, ok := o1.(*v1beta1.Ingress)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1beta1.Ingress", reflect.TypeOf(o1))
		return false
	}
	ing2, ok := o2.(*v1beta1.Ingress)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1beta1.Ingress", reflect.TypeOf(o2))
		return false
	}

	if ing1.Name != ing2.Name || ing1.Namespace != ing2.Namespace {
		return false
	}
	switch {
	case (ing1.Spec.Backend == nil) != (ing2.Spec.Backend == nil):
		return false
	case (ing1.Spec.Backend == nil) && (ing2.Spec.Backend == nil):
		return true
	}

	return ing1.Spec.Backend.ServicePort.IntVal ==
		ing2.Spec.Backend.ServicePort.IntVal &&
		ing1.Spec.Backend.ServicePort.StrVal ==
			ing2.Spec.Backend.ServicePort.StrVal
}

func equalV2CNP(o1, o2 interface{}) bool {
	cnp1, ok := o1.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *cilium_v2.CiliumNetworkPolicy", reflect.TypeOf(o1))
		return false
	}
	cnp2, ok := o2.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *cilium_v2.CiliumNetworkPolicy", reflect.TypeOf(o2))
		return false
	}
	return cnp1.Name == cnp2.Name &&
		cnp1.Namespace == cnp2.Namespace &&
		comparator.MapStringEquals(cnp1.GetAnnotations(), cnp2.GetAnnotations()) &&
		reflect.DeepEqual(cnp1.Spec, cnp2.Spec) &&
		reflect.DeepEqual(cnp1.Specs, cnp2.Specs)
}

func equalV1Pod(o1, o2 interface{}) bool {
	pod1, ok := o1.(*v1.Pod)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Pod", reflect.TypeOf(o1))
		return false
	}
	pod2, ok := o2.(*v1.Pod)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Pod", reflect.TypeOf(o2))
		return false
	}

	// We only care about the HostIP, the PodIP and the labels of the pods.
	if pod1.Status.PodIP != pod2.Status.PodIP ||
		pod1.Status.HostIP != pod2.Status.HostIP {
		return false
	}
	oldPodLabels := pod1.GetLabels()
	newPodLabels := pod2.GetLabels()
	return comparator.MapStringEquals(oldPodLabels, newPodLabels)
}

func equalV1Node(o1, o2 interface{}) bool {
	node1, ok := o1.(*v1.Node)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Node", reflect.TypeOf(o1))
		return false
	}
	node2, ok := o2.(*v1.Node)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Node", reflect.TypeOf(o2))
		return false
	}
	// The only information we care about the node is it's annotations, in
	// particularly the CiliumHostIP annotation.
	return node1.GetObjectMeta().GetName() == node2.GetObjectMeta().GetName() &&
		node1.GetAnnotations()[annotation.CiliumHostIP] == node2.GetAnnotations()[annotation.CiliumHostIP]
}

func equalV1Namespace(o1, o2 interface{}) bool {
	ns1, ok := o1.(*v1.Namespace)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Namespace", reflect.TypeOf(o1))
		return false
	}
	ns2, ok := o2.(*v1.Namespace)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Namespace", reflect.TypeOf(o2))
		return false
	}
	// we only care about namespace labels.
	return ns1.Name == ns2.Name &&
		comparator.MapStringEquals(ns1.GetLabels(), ns2.GetLabels())
}
