// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/comparator"
	dpTypes "github.com/cilium/cilium/pkg/datapath/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discover_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_discover_v1beta1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1beta1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func ObjToV1NetworkPolicy(obj interface{}) *slim_networkingv1.NetworkPolicy {
	k8sNP, ok := obj.(*slim_networkingv1.NetworkPolicy)
	if ok {
		return k8sNP
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		k8sNP, ok := deletedObj.Obj.(*slim_networkingv1.NetworkPolicy)
		if ok {
			return k8sNP
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 NetworkPolicy")
	return nil
}

func ObjToV1Ingress(obj interface{}) *slim_networkingv1.Ingress {
	ing, ok := obj.(*slim_networkingv1.Ingress)
	if ok {
		return ing
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		svc, ok := deletedObj.Obj.(*slim_networkingv1.Ingress)
		if ok {
			return svc
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v1 Ingress")
	return nil
}

func ObjToV1IngressClass(obj interface{}) *slim_networkingv1.IngressClass {
	ic, ok := obj.(*slim_networkingv1.IngressClass)
	if ok {
		return ic
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ic, ok := deletedObj.Obj.(*slim_networkingv1.IngressClass)
		if ok {
			return ic
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v1 IngressClass")
	return nil
}

func ObjToV1Services(obj interface{}) *slim_corev1.Service {
	svc, ok := obj.(*slim_corev1.Service)
	if ok {
		return svc
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		svc, ok := deletedObj.Obj.(*slim_corev1.Service)
		if ok {
			return svc
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Service")
	return nil
}

func ObjToV1Endpoints(obj interface{}) *slim_corev1.Endpoints {
	ep, ok := obj.(*slim_corev1.Endpoints)
	if ok {
		return ep
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ep, ok := deletedObj.Obj.(*slim_corev1.Endpoints)
		if ok {
			return ep
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Endpoints")
	return nil
}

func ObjToV1Beta1EndpointSlice(obj interface{}) *slim_discover_v1beta1.EndpointSlice {
	ep, ok := obj.(*slim_discover_v1beta1.EndpointSlice)
	if ok {
		return ep
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ep, ok := deletedObj.Obj.(*slim_discover_v1beta1.EndpointSlice)
		if ok {
			return ep
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1beta1 EndpointSlice")
	return nil
}

func ObjToV1EndpointSlice(obj interface{}) *slim_discover_v1.EndpointSlice {
	ep, ok := obj.(*slim_discover_v1.EndpointSlice)
	if ok {
		return ep
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ep, ok := deletedObj.Obj.(*slim_discover_v1.EndpointSlice)
		if ok {
			return ep
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 EndpointSlice")
	return nil
}

func ObjToSlimCNP(obj interface{}) *types.SlimCNP {
	cnp, ok := obj.(*types.SlimCNP)
	if ok {
		return cnp
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cnp, ok := deletedObj.Obj.(*types.SlimCNP)
		if ok {
			return cnp
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v2 CiliumNetworkPolicy")
	return nil
}

func ObjTov1Pod(obj interface{}) *slim_corev1.Pod {
	pod, ok := obj.(*slim_corev1.Pod)
	if ok {
		return pod
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		pod, ok := deletedObj.Obj.(*slim_corev1.Pod)
		if ok {
			return pod
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Pod")
	return nil
}

func ObjToV1Node(obj interface{}) *v1.Node {
	node, ok := obj.(*v1.Node)
	if ok {
		return node
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		node, ok := deletedObj.Obj.(*v1.Node)
		if ok {
			return node
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Node")
	return nil
}

func ObjToV1Namespace(obj interface{}) *slim_corev1.Namespace {
	ns, ok := obj.(*slim_corev1.Namespace)
	if ok {
		return ns
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ns, ok := deletedObj.Obj.(*slim_corev1.Namespace)
		if ok {
			return ns
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Namespace")
	return nil
}

func ObjToV1PartialObjectMetadata(obj interface{}) *slim_metav1.PartialObjectMetadata {
	pom, ok := obj.(*slim_metav1.PartialObjectMetadata)
	if ok {
		return pom
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		pom, ok := deletedObj.Obj.(*slim_metav1.PartialObjectMetadata)
		if ok {
			return pom
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 PartialObjectMetadata")
	return nil
}

func ObjToV1Secret(obj interface{}) *slim_corev1.Secret {
	secret, ok := obj.(*slim_corev1.Secret)
	if ok {
		return secret
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		secret, ok := deletedObj.Obj.(*slim_corev1.Secret)
		if ok {
			return secret
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid k8s v1 Secret")
	return nil
}

func EqualV1Services(k8sSVC1, k8sSVC2 *slim_corev1.Service, nodeAddressing dpTypes.NodeAddressing) bool {
	// Service annotations are used to mark services as global, shared, etc.
	if !comparator.MapStringEquals(k8sSVC1.GetAnnotations(), k8sSVC2.GetAnnotations()) {
		return false
	}

	svcID1, svc1 := ParseService(k8sSVC1, nodeAddressing)
	svcID2, svc2 := ParseService(k8sSVC2, nodeAddressing)

	if svcID1 != svcID2 {
		return false
	}

	// Please write all the equalness logic inside the K8sServiceInfo.Equals()
	// method.
	return svc1.DeepEqual(svc2)
}

// AnnotationsEqual returns whether the annotation with any key in
// relevantAnnotations is equal in anno1 and anno2.
func AnnotationsEqual(relevantAnnotations []string, anno1, anno2 map[string]string) bool {
	for _, an := range relevantAnnotations {
		if anno1[an] != anno2[an] {
			return false
		}
	}
	return true
}

func convertToK8sServicePorts(ports []v1.ServicePort) []slim_corev1.ServicePort {
	if ports == nil {
		return nil
	}

	slimPorts := make([]slim_corev1.ServicePort, 0, len(ports))
	for _, v1Port := range ports {
		slimPorts = append(slimPorts,
			slim_corev1.ServicePort{
				Name:     v1Port.Name,
				Protocol: slim_corev1.Protocol(v1Port.Protocol),
				Port:     v1Port.Port,
				NodePort: v1Port.NodePort,
			},
		)
	}
	return slimPorts
}

func ConvertToK8sV1ServicePorts(slimPorts []slim_corev1.ServicePort) []v1.ServicePort {
	if slimPorts == nil {
		return nil
	}

	ports := make([]v1.ServicePort, 0, len(slimPorts))
	for _, port := range slimPorts {
		ports = append(ports,
			v1.ServicePort{
				Name:     port.Name,
				Protocol: v1.Protocol(port.Protocol),
				Port:     port.Port,
				NodePort: port.NodePort,
			},
		)
	}
	return ports
}

func convertToK8sServiceAffinityConfig(saCfg *v1.SessionAffinityConfig) *slim_corev1.SessionAffinityConfig {
	if saCfg == nil {
		return nil
	}

	if saCfg.ClientIP == nil {
		return &slim_corev1.SessionAffinityConfig{}
	}

	return &slim_corev1.SessionAffinityConfig{
		ClientIP: &slim_corev1.ClientIPConfig{
			TimeoutSeconds: saCfg.ClientIP.TimeoutSeconds,
		},
	}
}

func ConvertToK8sV1ServiceAffinityConfig(saCfg *slim_corev1.SessionAffinityConfig) *v1.SessionAffinityConfig {
	if saCfg == nil {
		return nil
	}

	if saCfg.ClientIP == nil {
		return &v1.SessionAffinityConfig{}
	}

	return &v1.SessionAffinityConfig{
		ClientIP: &v1.ClientIPConfig{
			TimeoutSeconds: saCfg.ClientIP.TimeoutSeconds,
		},
	}
}

func convertToK8sLoadBalancerIngress(lbIngs []v1.LoadBalancerIngress) []slim_corev1.LoadBalancerIngress {
	if lbIngs == nil {
		return nil
	}

	slimLBIngs := make([]slim_corev1.LoadBalancerIngress, 0, len(lbIngs))
	for _, lbIng := range lbIngs {
		slimLBIngs = append(slimLBIngs,
			slim_corev1.LoadBalancerIngress{
				IP: lbIng.IP,
			},
		)
	}
	return slimLBIngs
}

func ConvertToK8sV1LoadBalancerIngress(slimLBIngs []slim_corev1.LoadBalancerIngress) []v1.LoadBalancerIngress {
	if slimLBIngs == nil {
		return nil
	}

	lbIngs := make([]v1.LoadBalancerIngress, 0, len(slimLBIngs))
	for _, lbIng := range slimLBIngs {
		var ports []v1.PortStatus
		for _, port := range lbIng.Ports {
			ports = append(ports, v1.PortStatus{
				Port:     port.Port,
				Protocol: v1.Protocol(port.Protocol),
				Error:    port.Error,
			})
		}
		lbIngs = append(lbIngs,
			v1.LoadBalancerIngress{
				IP:       lbIng.IP,
				Hostname: lbIng.Hostname,
				Ports:    ports,
			},
		)
	}
	return lbIngs
}

func ConvertToNetworkV1IngressLoadBalancerIngress(slimLBIngs []slim_corev1.LoadBalancerIngress) []networkingv1.IngressLoadBalancerIngress {
	if slimLBIngs == nil {
		return nil
	}

	ingLBIngs := make([]networkingv1.IngressLoadBalancerIngress, 0, len(slimLBIngs))
	for _, lbIng := range slimLBIngs {
		ports := make([]networkingv1.IngressPortStatus, 0, len(lbIng.Ports))
		for _, port := range lbIng.Ports {
			ports = append(ports, networkingv1.IngressPortStatus{
				Port:     port.Port,
				Protocol: v1.Protocol(port.Protocol),
				Error:    port.Error,
			})
		}
		ingLBIngs = append(ingLBIngs,
			networkingv1.IngressLoadBalancerIngress{
				IP:       lbIng.IP,
				Hostname: lbIng.Hostname,
				Ports:    ports,
			})
	}
	return ingLBIngs
}

func ConvertToSlimIngressLoadBalancerStatus(slimLBStatus *slim_corev1.LoadBalancerStatus) *slim_networkingv1.IngressLoadBalancerStatus {
	ingLBIngs := make([]slim_networkingv1.IngressLoadBalancerIngress, 0, len(slimLBStatus.Ingress))
	for _, lbIng := range slimLBStatus.Ingress {
		ports := make([]slim_networkingv1.IngressPortStatus, 0, len(lbIng.Ports))
		for _, port := range lbIng.Ports {
			ports = append(ports, slim_networkingv1.IngressPortStatus{
				Port:     port.Port,
				Protocol: slim_corev1.Protocol(port.Protocol),
				Error:    port.Error,
			})
		}
		ingLBIngs = append(ingLBIngs,
			slim_networkingv1.IngressLoadBalancerIngress{
				IP:       lbIng.IP,
				Hostname: lbIng.Hostname,
				Ports:    ports,
			})
	}
	return &slim_networkingv1.IngressLoadBalancerStatus{
		Ingress: ingLBIngs,
	}
}

// ConvertToK8sService converts a *v1.Service into a
// *slim_corev1.Service or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *slim_corev1.Service in its Obj.
// If the given obj can't be cast into either *slim_corev1.Service
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToK8sService(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *v1.Service:
		return &slim_corev1.Service{
			TypeMeta: slim_metav1.TypeMeta{
				Kind:       concreteObj.TypeMeta.Kind,
				APIVersion: concreteObj.TypeMeta.APIVersion,
			},
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.ObjectMeta.Name,
				Namespace:       concreteObj.ObjectMeta.Namespace,
				ResourceVersion: concreteObj.ObjectMeta.ResourceVersion,
				UID:             concreteObj.ObjectMeta.UID,
				Labels:          concreteObj.ObjectMeta.Labels,
				Annotations:     concreteObj.ObjectMeta.Annotations,
			},
			Spec: slim_corev1.ServiceSpec{
				Ports:                 convertToK8sServicePorts(concreteObj.Spec.Ports),
				Selector:              concreteObj.Spec.Selector,
				ClusterIP:             concreteObj.Spec.ClusterIP,
				Type:                  slim_corev1.ServiceType(concreteObj.Spec.Type),
				ExternalIPs:           concreteObj.Spec.ExternalIPs,
				SessionAffinity:       slim_corev1.ServiceAffinity(concreteObj.Spec.SessionAffinity),
				LoadBalancerIP:        concreteObj.Spec.LoadBalancerIP,
				ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyType(concreteObj.Spec.ExternalTrafficPolicy),
				HealthCheckNodePort:   concreteObj.Spec.HealthCheckNodePort,
				SessionAffinityConfig: convertToK8sServiceAffinityConfig(concreteObj.Spec.SessionAffinityConfig),
			},
			Status: slim_corev1.ServiceStatus{
				LoadBalancer: slim_corev1.LoadBalancerStatus{
					Ingress: convertToK8sLoadBalancerIngress(concreteObj.Status.LoadBalancer.Ingress),
				},
			},
		}
	case cache.DeletedFinalStateUnknown:
		svc, ok := concreteObj.Obj.(*v1.Service)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Service{
				TypeMeta: slim_metav1.TypeMeta{
					Kind:       svc.TypeMeta.Kind,
					APIVersion: svc.TypeMeta.APIVersion,
				},
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            svc.ObjectMeta.Name,
					Namespace:       svc.ObjectMeta.Namespace,
					ResourceVersion: svc.ObjectMeta.ResourceVersion,
					UID:             svc.ObjectMeta.UID,
					Labels:          svc.ObjectMeta.Labels,
					Annotations:     svc.ObjectMeta.Annotations,
				},
				Spec: slim_corev1.ServiceSpec{
					Ports:                 convertToK8sServicePorts(svc.Spec.Ports),
					Selector:              svc.Spec.Selector,
					ClusterIP:             svc.Spec.ClusterIP,
					Type:                  slim_corev1.ServiceType(svc.Spec.Type),
					ExternalIPs:           svc.Spec.ExternalIPs,
					SessionAffinity:       slim_corev1.ServiceAffinity(svc.Spec.SessionAffinity),
					LoadBalancerIP:        svc.Spec.LoadBalancerIP,
					ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyType(svc.Spec.ExternalTrafficPolicy),
					HealthCheckNodePort:   svc.Spec.HealthCheckNodePort,
					SessionAffinityConfig: convertToK8sServiceAffinityConfig(svc.Spec.SessionAffinityConfig),
				},
				Status: slim_corev1.ServiceStatus{
					LoadBalancer: slim_corev1.LoadBalancerStatus{
						Ingress: convertToK8sLoadBalancerIngress(svc.Status.LoadBalancer.Ingress),
					},
				},
			},
		}
	default:
		return obj
	}
}

// ConvertToCCNP converts a *cilium_v2.CiliumClusterwideNetworkPolicy into a
// *types.SlimCNP without the Status field of the given CNP, or a
// cache.DeletedFinalStateUnknown into a cache.DeletedFinalStateUnknown with a
// *types.SlimCNP, also without the Status field of the given CNP, in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumClusterwideNetworkPolicy
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCCNP(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumClusterwideNetworkPolicy:
		ccnp := &types.SlimCNP{
			CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
				TypeMeta:   concreteObj.TypeMeta,
				ObjectMeta: concreteObj.ObjectMeta,
				Spec:       concreteObj.Spec,
				Specs:      concreteObj.Specs,
			},
		}
		return ccnp

	case cache.DeletedFinalStateUnknown:
		ccnp, ok := concreteObj.Obj.(*cilium_v2.CiliumClusterwideNetworkPolicy)
		if !ok {
			return obj
		}
		slimCNP := &types.SlimCNP{
			CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
				TypeMeta:   ccnp.TypeMeta,
				ObjectMeta: ccnp.ObjectMeta,
				Spec:       ccnp.Spec,
				Specs:      ccnp.Specs,
			},
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: slimCNP,
		}
		return dfsu

	default:
		return obj
	}
}

// ConvertToCNP converts a *cilium_v2.CiliumNetworkPolicy into a
// *types.SlimCNP without the Status field of the given CNP, or a
// cache.DeletedFinalStateUnknown into a cache.DeletedFinalStateUnknown with a
// *types.SlimCNP, also without the Status field of the given CNP, in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumNetworkPolicy
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCNP(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumNetworkPolicy:
		cnp := &types.SlimCNP{
			CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
				TypeMeta:   concreteObj.TypeMeta,
				ObjectMeta: concreteObj.ObjectMeta,
				Spec:       concreteObj.Spec,
				Specs:      concreteObj.Specs,
			},
		}
		return cnp
	case cache.DeletedFinalStateUnknown:
		cnp, ok := concreteObj.Obj.(*cilium_v2.CiliumNetworkPolicy)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta:   cnp.TypeMeta,
					ObjectMeta: cnp.ObjectMeta,
					Spec:       cnp.Spec,
					Specs:      cnp.Specs,
				},
			},
		}
		return dfsu
	default:
		return obj
	}
}

func convertToAddress(v1Addrs []v1.NodeAddress) []slim_corev1.NodeAddress {
	if v1Addrs == nil {
		return nil
	}

	addrs := make([]slim_corev1.NodeAddress, 0, len(v1Addrs))
	for _, addr := range v1Addrs {
		addrs = append(
			addrs,
			slim_corev1.NodeAddress{
				Type:    slim_corev1.NodeAddressType(addr.Type),
				Address: addr.Address,
			},
		)
	}
	return addrs
}

func convertToTaints(v1Taints []v1.Taint) []slim_corev1.Taint {
	if v1Taints == nil {
		return nil
	}

	taints := make([]slim_corev1.Taint, 0, len(v1Taints))
	for _, taint := range v1Taints {
		var ta *slim_metav1.Time
		if taint.TimeAdded != nil {
			t := slim_metav1.NewTime(taint.TimeAdded.Time)
			ta = &t
		}
		taints = append(
			taints,
			slim_corev1.Taint{
				Key:       taint.Key,
				Value:     taint.Value,
				Effect:    slim_corev1.TaintEffect(taint.Effect),
				TimeAdded: ta,
			},
		)
	}
	return taints
}

// ConvertToNode converts a *v1.Node into a
// *types.Node or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *types.Node in its Obj.
// If the given obj can't be cast into either *v1.Node
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToNode(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *v1.Node:
		p := &slim_corev1.Node{
			TypeMeta: slim_metav1.TypeMeta{
				Kind:       concreteObj.TypeMeta.Kind,
				APIVersion: concreteObj.TypeMeta.APIVersion,
			},
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.ObjectMeta.Name,
				Namespace:       concreteObj.ObjectMeta.Namespace,
				UID:             concreteObj.ObjectMeta.UID,
				ResourceVersion: concreteObj.ObjectMeta.ResourceVersion,
				Labels:          concreteObj.ObjectMeta.Labels,
				Annotations:     concreteObj.ObjectMeta.Annotations,
			},
			Spec: slim_corev1.NodeSpec{
				PodCIDR:  concreteObj.Spec.PodCIDR,
				PodCIDRs: concreteObj.Spec.PodCIDRs,
				Taints:   convertToTaints(concreteObj.Spec.Taints),
			},
			Status: slim_corev1.NodeStatus{
				Addresses: convertToAddress(concreteObj.Status.Addresses),
			},
		}
		return p
	case cache.DeletedFinalStateUnknown:
		node, ok := concreteObj.Obj.(*v1.Node)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Node{
				TypeMeta: slim_metav1.TypeMeta{
					Kind:       node.TypeMeta.Kind,
					APIVersion: node.TypeMeta.APIVersion,
				},
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            node.ObjectMeta.Name,
					Namespace:       node.ObjectMeta.Namespace,
					UID:             node.ObjectMeta.UID,
					ResourceVersion: node.ObjectMeta.ResourceVersion,
					Labels:          node.ObjectMeta.Labels,
					Annotations:     node.ObjectMeta.Annotations,
				},
				Spec: slim_corev1.NodeSpec{
					PodCIDR:  node.Spec.PodCIDR,
					PodCIDRs: node.Spec.PodCIDRs,
					Taints:   convertToTaints(node.Spec.Taints),
				},
				Status: slim_corev1.NodeStatus{
					Addresses: convertToAddress(node.Status.Addresses),
				},
			},
		}
		return dfsu
	default:
		return obj
	}
}

// ConvertToCiliumNode converts a *cilium_v2.CiliumNode into a
// *cilium_v2.CiliumNode or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *cilium_v2.CiliumNode in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumNode
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumNode(obj interface{}) interface{} {
	// TODO create a slim type of the CiliumNode
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumNode:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumNode, ok := concreteObj.Obj.(*cilium_v2.CiliumNode)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: ciliumNode,
		}
	default:
		return obj
	}
}

// ConvertToCiliumExternalWorkload converts a *cilium_v2.CiliumExternalWorkload into a
// *cilium_v2.CiliumExternalWorkload or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *cilium_v2.CiliumExternalWorkload in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumExternalWorkload
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumExternalWorkload(obj interface{}) interface{} {
	// TODO create a slim type of the CiliumExternalWorkload
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumExternalWorkload:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumExternalWorkload, ok := concreteObj.Obj.(*cilium_v2.CiliumExternalWorkload)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: ciliumExternalWorkload,
		}
	default:
		return obj
	}
}

// ConvertToCiliumLocalRedirectPolicy converts a *cilium_v2.CiliumLocalRedirectPolicy into a
// *cilium_v2.CiliumLocalRedirectPolicy or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *cilium_v2.CiliumLocalRedirectPolicy in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumLocalRedirectPolicy
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumLocalRedirectPolicy(obj interface{}) interface{} {
	// TODO create a slim type of the CiliumLocalRedirectPolicy
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumLocalRedirectPolicy:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumLocalRedirectPolicy, ok := concreteObj.Obj.(*cilium_v2.CiliumLocalRedirectPolicy)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: ciliumLocalRedirectPolicy,
		}
	default:
		return obj
	}
}

// ConvertToCiliumEgressGatewayPolicy converts a *cilium_v2.CiliumEgressGatewayPolicy into a
// *cilium_v2.CiliumEgressGatewayPolicy or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *cilium_v2.CiliumEgressGatewayPolicy in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumEgressGatewayPolicy
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumEgressGatewayPolicy(obj interface{}) interface{} {
	// TODO create a slim type of the CiliumEgressGatewayPolicy
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumEgressGatewayPolicy:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumEgressGatewayPolicy, ok := concreteObj.Obj.(*cilium_v2.CiliumEgressGatewayPolicy)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: ciliumEgressGatewayPolicy,
		}
	default:
		return obj
	}
}

// ConvertToCiliumClusterwideEnvoyConfig converts a *cilium_v2.CiliumClusterwideEnvoyConfig into a
// *cilium_v2.CiliumClusterwideEnvoyConfig or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *cilium_v2.CiliumClusterwideEnvoyConfig in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumClusterwideEnvoyConfig
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumClusterwideEnvoyConfig(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumClusterwideEnvoyConfig:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumClusterwideEnvoyConfig, ok := concreteObj.Obj.(*cilium_v2.CiliumClusterwideEnvoyConfig)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: ciliumClusterwideEnvoyConfig,
		}
	default:
		return obj
	}
}

// ConvertToCiliumEnvoyConfig converts a *cilium_v2.CiliumEnvoyConfig into a
// *cilium_v2.CiliumEnvoyConfig or a cache.DeletedFinalStateUnknown into
// a cache.DeletedFinalStateUnknown with a *cilium_v2.CiliumEnvoyConfig in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumEnvoyConfig
// nor cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumEnvoyConfig(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumEnvoyConfig:
		return concreteObj
	case cache.DeletedFinalStateUnknown:
		ciliumEnvoyConfig, ok := concreteObj.Obj.(*cilium_v2.CiliumEnvoyConfig)
		if !ok {
			return obj
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: ciliumEnvoyConfig,
		}
	default:
		return obj
	}
}

// ObjToCiliumNode attempts to cast object to a CiliumNode object and
// returns the CiliumNode objext if the cast succeeds. Otherwise, nil is returned.
func ObjToCiliumNode(obj interface{}) *cilium_v2.CiliumNode {
	cn, ok := obj.(*cilium_v2.CiliumNode)
	if ok {
		return cn
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cn, ok := deletedObj.Obj.(*cilium_v2.CiliumNode)
		if ok {
			return cn
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 CiliumNode")
	return nil
}

// ConvertToCiliumEndpoint converts a *cilium_v2.CiliumEndpoint into a
// *types.CiliumEndpoint or a cache.DeletedFinalStateUnknown into a
// cache.DeletedFinalStateUnknown with a *types.CiliumEndpoint in its Obj.
// If the given obj can't be cast into either *cilium_v2.CiliumEndpoint nor
// cache.DeletedFinalStateUnknown, the original obj is returned.
func ConvertToCiliumEndpoint(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumEndpoint:
		p := &types.CiliumEndpoint{
			TypeMeta: slim_metav1.TypeMeta{
				Kind:       concreteObj.TypeMeta.Kind,
				APIVersion: concreteObj.TypeMeta.APIVersion,
			},
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.ObjectMeta.Name,
				Namespace:       concreteObj.ObjectMeta.Namespace,
				UID:             concreteObj.ObjectMeta.UID,
				ResourceVersion: concreteObj.ObjectMeta.ResourceVersion,
				// We don't need to store labels nor annotations because
				// they are not used by the CEP handlers.
				Labels:      nil,
				Annotations: nil,
			},
			Encryption: func() *cilium_v2.EncryptionSpec {
				enc := concreteObj.Status.Encryption
				return &enc
			}(),
			Identity:   concreteObj.Status.Identity,
			Networking: concreteObj.Status.Networking,
			NamedPorts: concreteObj.Status.NamedPorts,
		}
		return p
	case cache.DeletedFinalStateUnknown:
		ciliumEndpoint, ok := concreteObj.Obj.(*cilium_v2.CiliumEndpoint)
		if !ok {
			return obj
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &types.CiliumEndpoint{
				TypeMeta: slim_metav1.TypeMeta{
					Kind:       ciliumEndpoint.TypeMeta.Kind,
					APIVersion: ciliumEndpoint.TypeMeta.APIVersion,
				},
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumEndpoint.ObjectMeta.Name,
					Namespace:       ciliumEndpoint.ObjectMeta.Namespace,
					UID:             ciliumEndpoint.ObjectMeta.UID,
					ResourceVersion: ciliumEndpoint.ObjectMeta.ResourceVersion,
					// We don't need to store labels nor annotations because
					// they are not used by the CEP handlers.
					Labels:      nil,
					Annotations: nil,
				},
				Encryption: func() *cilium_v2.EncryptionSpec {
					enc := ciliumEndpoint.Status.Encryption
					return &enc
				}(),
				Identity:   ciliumEndpoint.Status.Identity,
				Networking: ciliumEndpoint.Status.Networking,
				NamedPorts: ciliumEndpoint.Status.NamedPorts,
			},
		}
		return dfsu
	default:
		return obj
	}
}

// ObjToCiliumEndpoint attempts to cast object to a CiliumEndpoint object
// and returns the CiliumEndpoint object if the cast succeeds. Otherwise, nil is returned.
func ObjToCiliumEndpoint(obj interface{}) *types.CiliumEndpoint {
	ce, ok := obj.(*types.CiliumEndpoint)
	if ok {
		return ce
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ce, ok := deletedObj.Obj.(*types.CiliumEndpoint)
		if ok {
			return ce
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 CiliumEndpoint")
	return nil
}

// ObjToCLRP attempts to cast object to a CLRP object and
// returns the CLRP object if the cast succeeds. Otherwise, nil is returned.
func ObjToCLRP(obj interface{}) *cilium_v2.CiliumLocalRedirectPolicy {
	cLRP, ok := obj.(*cilium_v2.CiliumLocalRedirectPolicy)
	if ok {
		return cLRP
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cn, ok := deletedObj.Obj.(*cilium_v2.CiliumLocalRedirectPolicy)
		if ok {
			return cn
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 Cilium Local Redirect Policy")
	return nil
}

// ObjToCEGP attempts to cast object to a CEGP object and
// returns the CEGP object if the cast succeeds. Otherwise, nil is returned.
func ObjToCEGP(obj interface{}) *cilium_v2.CiliumEgressGatewayPolicy {
	cEGP, ok := obj.(*cilium_v2.CiliumEgressGatewayPolicy)
	if ok {
		return cEGP
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cn, ok := deletedObj.Obj.(*cilium_v2.CiliumEgressGatewayPolicy)
		if ok {
			return cn
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 Cilium Egress Gateway Policy")
	return nil
}

// ObjToCiliumEndpointSlice attempts to cast object to a CiliumEndpointSlice object
// and returns a deep copy if the castin succeeds. Otherwise, nil is returned.
func ObjToCiliumEndpointSlice(obj interface{}) *cilium_v2alpha1.CiliumEndpointSlice {
	ces, ok := obj.(*cilium_v2alpha1.CiliumEndpointSlice)
	if ok {
		return ces
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ces, ok := deletedObj.Obj.(*cilium_v2alpha1.CiliumEndpointSlice)
		if ok {
			return ces
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid CiliumEndpointSlice")
	return nil
}

// ConvertCEPToCoreCEP converts a CiliumEndpoint to a CoreCiliumEndpoint
// containing only a minimal set of entities used to
func ConvertCEPToCoreCEP(cep *cilium_v2.CiliumEndpoint) *cilium_v2alpha1.CoreCiliumEndpoint {

	// Copy Networking field into core CEP
	var epNetworking *cilium_v2.EndpointNetworking
	if cep.Status.Networking != nil {
		epNetworking = new(cilium_v2.EndpointNetworking)
		cep.Status.Networking.DeepCopyInto(epNetworking)
	}
	var identityID int64 = 0
	if cep.Status.Identity != nil {
		identityID = cep.Status.Identity.ID
	}
	return &cilium_v2alpha1.CoreCiliumEndpoint{
		Name:       cep.GetName(),
		Networking: epNetworking,
		Encryption: cep.Status.Encryption,
		IdentityID: identityID,
		NamedPorts: cep.Status.NamedPorts.DeepCopy(),
	}
}

// ConvertCoreCiliumEndpointToTypesCiliumEndpoint converts CoreCiliumEndpoint object to types.CiliumEndpoint.
func ConvertCoreCiliumEndpointToTypesCiliumEndpoint(ccep *cilium_v2alpha1.CoreCiliumEndpoint, ns string) *types.CiliumEndpoint {
	return &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      ccep.Name,
			Namespace: ns,
		},
		Encryption: func() *cilium_v2.EncryptionSpec {
			enc := ccep.Encryption
			return &enc
		}(),
		Identity: &cilium_v2.EndpointIdentity{
			ID: ccep.IdentityID,
		},
		Networking: ccep.Networking,
		NamedPorts: ccep.NamedPorts,
	}
}

// ObjToCCEC attempts to cast object to a CCEC object and
// returns the object if the cast succeeds. Otherwise, nil is returned.
func ObjToCCEC(obj interface{}) *cilium_v2.CiliumClusterwideEnvoyConfig {
	ccec, ok := obj.(*cilium_v2.CiliumClusterwideEnvoyConfig)
	if ok {
		return ccec
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		ccec, ok := deletedObj.Obj.(*cilium_v2.CiliumClusterwideEnvoyConfig)
		if ok {
			return ccec
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 Cilium Clusterwide Envoy Config")
	return nil
}

// ObjToCEC attempts to cast object to a CEC object and
// returns the object if the cast succeeds. Otherwise, nil is returned.
func ObjToCEC(obj interface{}) *cilium_v2.CiliumEnvoyConfig {
	cec, ok := obj.(*cilium_v2.CiliumEnvoyConfig)
	if ok {
		return cec
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cec, ok := deletedObj.Obj.(*cilium_v2.CiliumEnvoyConfig)
		if ok {
			return cec
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 Cilium Envoy Config")
	return nil
}
