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

func EqualV1NetworkPolicy(np1, np2 *networkingv1.NetworkPolicy) bool {
	// As Cilium uses all of the Spec from a NP it's not probably not worth
	// it to create a dedicated deep equal	 function to compare both network
	// policies.
	return np1.Name == np2.Name &&
		np1.Namespace == np2.Namespace &&
		reflect.DeepEqual(np1.Spec, np2.Spec)
}

func EqualV1Services(svc1, svc2 *v1.Service) bool {
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

func EqualV1Endpoints(ep1, ep2 *v1.Endpoints) bool {
	// We only care about the Name, Namespace and Subsets of a particular
	// endpoint.
	return ep1.Name == ep2.Name &&
		ep1.Namespace == ep2.Namespace &&
		reflect.DeepEqual(ep1.Subsets, ep2.Subsets)
}

func EqualV1beta1Ingress(ing1, ing2 *v1beta1.Ingress) bool {
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

func EqualV2CNP(cnp1, cnp2 *cilium_v2.CiliumNetworkPolicy) bool {
	return cnp1.Name == cnp2.Name &&
		cnp1.Namespace == cnp2.Namespace &&
		comparator.MapStringEquals(cnp1.GetAnnotations(), cnp2.GetAnnotations()) &&
		reflect.DeepEqual(cnp1.Spec, cnp2.Spec) &&
		reflect.DeepEqual(cnp1.Specs, cnp2.Specs)
}

func EqualV1Pod(pod1, pod2 *v1.Pod) bool {
	// We only care about the HostIP, the PodIP and the labels of the pods.
	if pod1.Status.PodIP != pod2.Status.PodIP ||
		pod1.Status.HostIP != pod2.Status.HostIP {
		return false
	}
	oldPodLabels := pod1.GetLabels()
	newPodLabels := pod2.GetLabels()
	return comparator.MapStringEquals(oldPodLabels, newPodLabels)
}

func EqualV1Node(node1, node2 *v1.Node) bool {
	// The only information we care about the node is it's annotations, in
	// particularly the CiliumHostIP annotation.
	return node1.GetObjectMeta().GetName() == node2.GetObjectMeta().GetName() &&
		node1.GetAnnotations()[annotation.CiliumHostIP] == node2.GetAnnotations()[annotation.CiliumHostIP]
}

func EqualV1Namespace(ns1, ns2 *v1.Namespace) bool {
	// we only care about namespace labels.
	return ns1.Name == ns2.Name &&
		comparator.MapStringEquals(ns1.GetLabels(), ns2.GetLabels())
}
