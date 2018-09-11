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

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	versionedClient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioned"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func init() {
	utils.RegisterObject(
		&networkingv1.NetworkPolicy{},
		"networkpolicies",
		copyObjToV1NetworkPolicy,
		listV1NetworkPolicies,
		equalV1NetworkPolicy,
	)

	utils.RegisterObject(
		&v1.Service{},
		"services",
		copyObjToV1Services,
		listV1Services,
		equalV1Services,
	)

	utils.RegisterObject(
		&v1.Endpoints{},
		"endpoints",
		copyObjToV1Endpoints,
		listV1Endpoints,
		equalV1Endpoints,
	)

	utils.RegisterObject(
		&v1beta1.Ingress{},
		"ingresses",
		copyObjToV1beta1Ingress,
		listV1beta1Ingress,
		equalV1beta1Ingress,
	)

	utils.RegisterObject(
		&cilium_v2.CiliumNetworkPolicy{},
		"ciliumnetworkpolicies",
		copyObjToV2CNP,
		listV2CNP,
		equalV2CNP,
	)

	utils.RegisterObject(
		&v1.Pod{},
		"pods",
		copyObjToV1Pod,
		listV1Pod,
		equalV1Pod,
	)

	utils.RegisterObject(
		&v1.Node{},
		"nodes",
		copyObjToV1Node,
		listV1Node,
		equalV1Node,
	)

	utils.RegisterObject(
		&v1.Namespace{},
		"namespaces",
		copyObjToV1Namespace,
		listV1Namespace,
		equalV1Namespace,
	)
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

func listV1NetworkPolicies(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.NetworkingV1().NetworkPolicies("").List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV1Services(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.CoreV1().Services("").List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV1Endpoints(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.CoreV1().Endpoints("").List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV1beta1Ingress(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.ExtensionsV1beta1().Ingresses("").List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV2CNP(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(versionedClient.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'versionedClient.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.CiliumV2().CiliumNetworkPolicies("").List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV1Pod(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.CoreV1().Pods("").List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV1Node(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.CoreV1().Nodes().List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
}

func listV1Namespace(client interface{}) func() (versioned.Map, error) {
	k8sClient, ok := client.(kubernetes.Interface)
	if !ok {
		log.Panicf("Invalid resource type %s: expecting 'kubernetes.Interface'", reflect.TypeOf(client))
	}
	return func() (versioned.Map, error) {
		m := versioned.NewMap()
		// Limit the number of elements to avoid network congestion every N minutes
		lo := meta_v1.ListOptions{Limit: 50}
		for {
			list, err := k8sClient.CoreV1().Namespaces().List(lo)
			if err != nil {
				return nil, err
			}
			lo.Continue = list.Continue
			for i := range list.Items {
				m.Add(utils.GetVerStructFrom(&list.Items[i]))
			}
			if lo.Continue == "" {
				break
			}
		}
		return m, nil
	}
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
	_, ok := o1.(*v1.Service)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Service", reflect.TypeOf(o1))
		return false
	}
	_, ok = o1.(*v1.Service)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Service", reflect.TypeOf(o2))
		return false
	}
	// FIXME write dedicated deep equal function
	return false
}

func equalV1Endpoints(o1, o2 interface{}) bool {
	_, ok := o1.(*v1.Endpoints)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Endpoints", reflect.TypeOf(o1))
		return false
	}
	_, ok = o1.(*v1.Endpoints)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Endpoints", reflect.TypeOf(o2))
		return false
	}
	// FIXME write dedicated deep equal function
	return false
}

func equalV1beta1Ingress(o1, o2 interface{}) bool {
	_, ok := o1.(*v1beta1.Ingress)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1beta1.Ingress", reflect.TypeOf(o1))
		return false
	}
	_, ok = o1.(*v1beta1.Ingress)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1beta1.Ingress", reflect.TypeOf(o2))
		return false
	}
	// FIXME write dedicated deep equal function
	return false
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
		reflect.DeepEqual(cnp1.Spec, cnp2.Spec) &&
		reflect.DeepEqual(cnp1.Specs, cnp2.Specs)
}

func equalV1Pod(o1, o2 interface{}) bool {
	_, ok := o1.(*v1.Pod)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Pod", reflect.TypeOf(o1))
		return false
	}
	_, ok = o1.(*v1.Pod)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Pod", reflect.TypeOf(o2))
		return false
	}
	// FIXME write dedicated deep equal function
	return false
}

func equalV1Node(o1, o2 interface{}) bool {
	_, ok := o1.(*v1.Node)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Node", reflect.TypeOf(o1))
		return false
	}
	_, ok = o1.(*v1.Node)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Node", reflect.TypeOf(o2))
		return false
	}
	// FIXME write dedicated deep equal function
	return false
}

func equalV1Namespace(o1, o2 interface{}) bool {
	_, ok := o1.(*v1.Namespace)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Namespace", reflect.TypeOf(o1))
		return false
	}
	_, ok = o1.(*v1.Namespace)
	if !ok {
		log.Panicf("Invalid resource type %q, expecting *v1.Namespace", reflect.TypeOf(o2))
		return false
	}
	// FIXME write dedicated deep equal function
	return false
}
