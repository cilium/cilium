// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"maps"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/tools/cache"

	dpTypes "github.com/cilium/cilium/pkg/datapath/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CastInformerEvent tries to cast obj to type typ, directly
// or by DeletedFinalStateUnknown type. It returns nil and logs
// an error if obj doesn't contain type typ.
func CastInformerEvent[typ any](obj interface{}) *typ {
	k8sObj, ok := obj.(*typ)
	if ok {
		return k8sObj
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		k8sObj, ok := deletedObj.Obj.(*typ)
		if ok {
			return k8sObj
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warnf("Ignoring invalid type, expected: %T", new(typ))
	return nil
}

func EqualV1Services(k8sSVC1, k8sSVC2 *slim_corev1.Service, nodeAddressing dpTypes.NodeAddressing) bool {
	// Service annotations are used to mark services as global, shared, etc.
	if !maps.Equal(k8sSVC1.GetAnnotations(), k8sSVC2.GetAnnotations()) {
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

// TransformToK8sService transforms a *v1.Service into a *slim_corev1.Service
// or a cache.DeletedFinalStateUnknown into a cache.DeletedFinalStateUnknown
// with a *slim_corev1.Service in its Obj. If obj is a *slim_corev1.Service
// or a cache.DeletedFinalStateUnknown with a *slim_corev1.Service in its Obj,
// obj is returned without any transformations. If the given obj can't be cast
// into either *slim_corev1.Service nor cache.DeletedFinalStateUnknown, an error
// is returned.
func TransformToK8sService(obj interface{}) (interface{}, error) {
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
		}, nil
	case *slim_corev1.Service:
		return obj, nil
	case cache.DeletedFinalStateUnknown:
		if _, ok := concreteObj.Obj.(*slim_corev1.Service); ok {
			return obj, nil
		}
		svc, ok := concreteObj.Obj.(*v1.Service)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
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
		}, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

// TransformToCCNP transforms a *cilium_v2.CiliumClusterwideNetworkPolicy into a
// *types.SlimCNP without the Status field of the given CNP, or a
// cache.DeletedFinalStateUnknown into a cache.DeletedFinalStateUnknown with a
// *types.SlimCNP, also without the Status field of the given CNP, in its Obj.
// If obj is a *types.SlimCNP or a cache.DeletedFinalStateUnknown with a *types.SlimCNP
// in its Obj, obj is returned without any transformations. If the given obj can't be
// cast into either *cilium_v2.CiliumClusterwideNetworkPolicy nor
// cache.DeletedFinalStateUnknown, an error is returned.
func TransformToCCNP(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumClusterwideNetworkPolicy:
		return &types.SlimCNP{
			CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
				TypeMeta:   concreteObj.TypeMeta,
				ObjectMeta: concreteObj.ObjectMeta,
				Spec:       concreteObj.Spec,
				Specs:      concreteObj.Specs,
			},
		}, nil
	case *types.SlimCNP:
		return obj, nil
	case cache.DeletedFinalStateUnknown:
		if _, ok := concreteObj.Obj.(*types.SlimCNP); ok {
			return obj, nil
		}
		ccnp, ok := concreteObj.Obj.(*cilium_v2.CiliumClusterwideNetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
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
		return dfsu, nil

	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

// TransformToCNP transforms a *cilium_v2.CiliumNetworkPolicy into a
// *types.SlimCNP without the Status field of the given CNP, or a
// cache.DeletedFinalStateUnknown into a cache.DeletedFinalStateUnknown with a
// *types.SlimCNP, also without the Status field of the given CNP, in its Obj.
// If obj is a *types.SlimCNP or a cache.DeletedFinalStateUnknown with a
// *types.SlimCNP in its Obj, obj is returned without any transformations.
// If the given obj can't be cast into either *cilium_v2.CiliumNetworkPolicy
// nor cache.DeletedFinalStateUnknown, an error is returned.
func TransformToCNP(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumNetworkPolicy:
		return &types.SlimCNP{
			CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
				TypeMeta:   concreteObj.TypeMeta,
				ObjectMeta: concreteObj.ObjectMeta,
				Spec:       concreteObj.Spec,
				Specs:      concreteObj.Specs,
			},
		}, nil
	case *types.SlimCNP:
		return obj, nil
	case cache.DeletedFinalStateUnknown:
		if _, ok := concreteObj.Obj.(*types.SlimCNP); ok {
			return obj, nil
		}
		cnp, ok := concreteObj.Obj.(*cilium_v2.CiliumNetworkPolicy)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		return cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta:   cnp.TypeMeta,
					ObjectMeta: cnp.ObjectMeta,
					Spec:       cnp.Spec,
					Specs:      cnp.Specs,
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
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

// TransformToCiliumEndpoint transforms a *cilium_v2.CiliumEndpoint into a
// *types.CiliumEndpoint or a cache.DeletedFinalStateUnknown into a
// cache.DeletedFinalStateUnknown with a *types.CiliumEndpoint in its Obj.
// If obj is a *types.CiliumEndpoint or a cache.DeletedFinalStateUnknown with
// a *types.CiliumEndpoint in its Obj, obj is returned without any transformations.
// If the given obj can't be cast into either *cilium_v2.CiliumEndpoint nor
// cache.DeletedFinalStateUnknown, an error is returned.
func TransformToCiliumEndpoint(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *cilium_v2.CiliumEndpoint:
		return &types.CiliumEndpoint{
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
		}, nil
	case *types.CiliumEndpoint:
		return obj, nil
	case cache.DeletedFinalStateUnknown:
		if _, ok := concreteObj.Obj.(*types.CiliumEndpoint); ok {
			return obj, nil
		}
		ciliumEndpoint, ok := concreteObj.Obj.(*cilium_v2.CiliumEndpoint)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		return cache.DeletedFinalStateUnknown{
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
		}, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
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
