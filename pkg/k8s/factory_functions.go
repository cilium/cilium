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
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
)

func CopyObjToV1NetworkPolicy(obj interface{}) *types.NetworkPolicy {
	k8sNP, ok := obj.(*types.NetworkPolicy)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 NetworkPolicy")
		return nil
	}
	return k8sNP.DeepCopy()
}

func CopyObjToV1Services(obj interface{}) *types.Service {
	svc, ok := obj.(*types.Service)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Service")
		return nil
	}
	return svc.DeepCopy()
}

func CopyObjToV1Endpoints(obj interface{}) *types.Endpoints {
	ep, ok := obj.(*types.Endpoints)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Endpoints")
		return nil
	}
	return ep.DeepCopy()
}

func CopyObjToV1beta1Ingress(obj interface{}) *types.Ingress {
	ing, ok := obj.(*types.Ingress)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1beta1 Ingress")
		return nil
	}
	return ing.DeepCopy()
}

func CopyObjToV2CNP(obj interface{}) *types.SlimCNP {
	cnp, ok := obj.(*types.SlimCNP)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v2 CiliumNetworkPolicy")
		return nil
	}
	return cnp.DeepCopy()
}

func CopyObjToV1Pod(obj interface{}) *types.Pod {
	pod, ok := obj.(*types.Pod)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Pod")
		return nil
	}
	return pod.DeepCopy()
}

func CopyObjToV1Node(obj interface{}) *types.Node {
	node, ok := obj.(*types.Node)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Node")
		return nil
	}
	return node.DeepCopy()
}

func CopyObjToV1Namespace(obj interface{}) *types.Namespace {
	ns, ok := obj.(*types.Namespace)
	if !ok {
		log.WithField(logfields.Object, logfields.Repr(obj)).
			Warn("Ignoring invalid k8s v1 Namespace")
		return nil
	}
	return ns.DeepCopy()
}

func EqualV1NetworkPolicy(np1, np2 *types.NetworkPolicy) bool {
	// As Cilium uses all of the Spec from a NP it's not probably not worth
	// it to create a dedicated deep equal	 function to compare both network
	// policies.
	return np1.Name == np2.Name &&
		np1.Namespace == np2.Namespace &&
		reflect.DeepEqual(np1.Spec, np2.Spec)
}

func EqualV1Services(svc1, svc2 *types.Service) bool {
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

func EqualV1Endpoints(ep1, ep2 *types.Endpoints) bool {
	// We only care about the Name, Namespace and Subsets of a particular
	// endpoint.
	return ep1.Name == ep2.Name &&
		ep1.Namespace == ep2.Namespace &&
		reflect.DeepEqual(ep1.Subsets, ep2.Subsets)
}

func EqualV1beta1Ingress(ing1, ing2 *types.Ingress) bool {
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

func EqualV2CNP(cnp1, cnp2 *types.SlimCNP) bool {
	if !(cnp1.Name == cnp2.Name && cnp1.Namespace == cnp2.Namespace) {
		return false
	}

	// Ignore v1.LastAppliedConfigAnnotation annotation
	lastAppliedCfgAnnotation1, ok1 := cnp1.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	lastAppliedCfgAnnotation2, ok2 := cnp2.GetAnnotations()[v1.LastAppliedConfigAnnotation]
	defer func() {
		if ok1 && cnp1.GetAnnotations() != nil {
			cnp1.GetAnnotations()[v1.LastAppliedConfigAnnotation] = lastAppliedCfgAnnotation1
		}
		if ok2 && cnp2.GetAnnotations() != nil {
			cnp2.GetAnnotations()[v1.LastAppliedConfigAnnotation] = lastAppliedCfgAnnotation2
		}
	}()
	delete(cnp1.GetAnnotations(), v1.LastAppliedConfigAnnotation)
	delete(cnp2.GetAnnotations(), v1.LastAppliedConfigAnnotation)

	return comparator.MapStringEquals(cnp1.GetAnnotations(), cnp2.GetAnnotations()) &&
		reflect.DeepEqual(cnp1.Spec, cnp2.Spec) &&
		reflect.DeepEqual(cnp1.Specs, cnp2.Specs)
}

func EqualV1Pod(pod1, pod2 *types.Pod) bool {
	// We only care about the HostIP, the PodIP and the labels of the pods.
	if pod1.StatusPodIP != pod2.StatusPodIP ||
		pod1.StatusHostIP != pod2.StatusHostIP {
		return false
	}
	oldPodLabels := pod1.GetLabels()
	newPodLabels := pod2.GetLabels()
	return comparator.MapStringEquals(oldPodLabels, newPodLabels)
}

func EqualV1Node(node1, node2 *types.Node) bool {
	if node1.GetObjectMeta().GetName() != node2.GetObjectMeta().GetName() {
		return false
	}

	anno1 := node1.GetAnnotations()
	anno2 := node2.GetAnnotations()
	annotationsWeCareAbout := []string{
		annotation.CiliumHostIP,
		annotation.CiliumHostIPv6,
		annotation.V4HealthName,
		annotation.V6HealthName,
	}
	for _, an := range annotationsWeCareAbout {
		if anno1[an] != anno2[an] {
			return false
		}
	}
	return true
}

func EqualV1Namespace(ns1, ns2 *types.Namespace) bool {
	// we only care about namespace labels.
	return ns1.Name == ns2.Name &&
		comparator.MapStringEquals(ns1.GetLabels(), ns2.GetLabels())
}

// ConvertToNetworkPolicy converts a *networkingv1.NetworkPolicy into a
// *types.NetworkPolicy
func ConvertToNetworkPolicy(obj interface{}) interface{} {
	netPol, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		return nil
	}
	// TODO check which fields we really need
	return &types.NetworkPolicy{
		NetworkPolicy: netPol,
	}
}

// ConvertToK8sService converts a *v1.Service into a *types.Service
func ConvertToK8sService(obj interface{}) interface{} {
	service, ok := obj.(*v1.Service)
	if !ok {
		return nil
	}
	// TODO check which fields we really need
	return &types.Service{
		Service: service,
	}
}

// ConvertToK8sEndpoints converts a *v1.Endpoints into a *types.Endpoints
func ConvertToK8sEndpoints(obj interface{}) interface{} {
	endpoints, ok := obj.(*v1.Endpoints)
	if !ok {
		return nil
	}
	// TODO check which fields we really need
	return &types.Endpoints{
		Endpoints: endpoints,
	}
}

// ConvertToIngress converts a *v1beta1.Ingress into a *v1beta1.Ingress
func ConvertToIngress(obj interface{}) interface{} {
	ingress, ok := obj.(*v1beta1.Ingress)
	if !ok {
		return nil
	}
	// TODO check which fields we really need
	return &types.Ingress{
		Ingress: ingress,
	}
}

// ConvertToCNPWithStatus converts a *cilium_v2.CiliumNetworkPolicy into a
// *types.SlimCNP
func ConvertToCNPWithStatus(obj interface{}) interface{} {
	cnp, ok := obj.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		return nil
	}
	slimCNP := &types.SlimCNP{
		CiliumNetworkPolicy: cnp,
	}
	return slimCNP
}

// ConvertToCNP converts a *cilium_v2.CiliumNetworkPolicy into a *types.SlimCNP
// without the Status field of the given CNP.
// WARNING calling this function will set *all* fields of the given CNP as
// empty.
func ConvertToCNP(obj interface{}) interface{} {
	cnp, ok := obj.(*cilium_v2.CiliumNetworkPolicy)
	if !ok {
		return nil
	}
	slimCNP := &types.SlimCNP{
		CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
			TypeMeta:   cnp.TypeMeta,
			ObjectMeta: cnp.ObjectMeta,
			Spec:       cnp.Spec,
			Specs:      cnp.Specs,
		},
	}
	*cnp = cilium_v2.CiliumNetworkPolicy{}
	return slimCNP
}

// ConvertToPod converts a *v1.Pod into a *types.Pod.
// WARNING calling this function will set *all* fields of the given Pod as
// empty.
func ConvertToPod(obj interface{}) interface{} {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return nil
	}
	p := &types.Pod{
		TypeMeta:        pod.TypeMeta,
		ObjectMeta:      pod.ObjectMeta,
		StatusPodIP:     pod.Status.PodIP,
		StatusHostIP:    pod.Status.HostIP,
		SpecHostNetwork: pod.Spec.HostNetwork,
	}
	*pod = v1.Pod{}
	return p
}

// ConvertToNode converts a *v1.Node into a *types.Node.
// WARNING calling this function will set *all* fields of the given Node as
// empty.
func ConvertToNode(obj interface{}) interface{} {
	node, ok := obj.(*v1.Node)
	if !ok {
		return nil
	}
	n := &types.Node{
		TypeMeta:        node.TypeMeta,
		ObjectMeta:      node.ObjectMeta,
		StatusAddresses: node.Status.Addresses,
		SpecPodCIDR:     node.Spec.PodCIDR,
	}
	*node = v1.Node{}
	return n
}

// ConvertToNamespace converts a *v1.Namespace into a *types.Namespace.
// WARNING calling this function will set *all* fields of the given Namespace as
// empty.
func ConvertToNamespace(obj interface{}) interface{} {
	namespace, ok := obj.(*v1.Namespace)
	if !ok {
		return nil
	}
	n := &types.Namespace{
		TypeMeta:   namespace.TypeMeta,
		ObjectMeta: namespace.ObjectMeta,
	}
	*namespace = v1.Namespace{}
	return n
}
