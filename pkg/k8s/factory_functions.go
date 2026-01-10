// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"

	"k8s.io/client-go/tools/cache"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

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

// TransformToCCNP transforms a *cilium_v2.CiliumClusterwideNetworkPolicy into a
// *types.SlimCNP without the Status field of the given CNP, or a
// cache.DeletedFinalStateUnknown into a cache.DeletedFinalStateUnknown with a
// *types.SlimCNP, also without the Status field of the given CNP, in its Obj.
// If obj is a *types.SlimCNP or a cache.DeletedFinalStateUnknown with a *types.SlimCNP
// in its Obj, obj is returned without any transformations. If the given obj can't be
// cast into either *cilium_v2.CiliumClusterwideNetworkPolicy nor
// cache.DeletedFinalStateUnknown, an error is returned.
func TransformToCCNP(obj any) (any, error) {
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
func TransformToCNP(obj any) (any, error) {
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

// TransformToCiliumEndpoint transforms a *cilium_v2.CiliumEndpoint into a
// *types.CiliumEndpoint or a cache.DeletedFinalStateUnknown into a
// cache.DeletedFinalStateUnknown with a *types.CiliumEndpoint in its Obj.
// If obj is a *types.CiliumEndpoint or a cache.DeletedFinalStateUnknown with
// a *types.CiliumEndpoint in its Obj, obj is returned without any transformations.
// If the given obj can't be cast into either *cilium_v2.CiliumEndpoint nor
// cache.DeletedFinalStateUnknown, an error is returned.
func TransformToCiliumEndpoint(obj any) (any, error) {
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
				// OwnerReferences is needed for ztunnel xDS to extract Pod UID.
				OwnerReferences: slim_metav1.SlimOwnerReferences(concreteObj.ObjectMeta.OwnerReferences),
			},
			Encryption: func() *cilium_v2.EncryptionSpec {
				enc := concreteObj.Status.Encryption
				return &enc
			}(),
			Identity:       concreteObj.Status.Identity,
			Networking:     concreteObj.Status.Networking,
			NamedPorts:     concreteObj.Status.NamedPorts,
			ServiceAccount: concreteObj.Status.ServiceAccount,
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
					// OwnerReferences is needed for ztunnel xDS to extract Pod UID.
					OwnerReferences: slim_metav1.SlimOwnerReferences(ciliumEndpoint.ObjectMeta.OwnerReferences),
				},
				Encryption: func() *cilium_v2.EncryptionSpec {
					enc := ciliumEndpoint.Status.Encryption
					return &enc
				}(),
				Identity:       ciliumEndpoint.Status.Identity,
				Networking:     ciliumEndpoint.Status.Networking,
				NamedPorts:     ciliumEndpoint.Status.NamedPorts,
				ServiceAccount: ciliumEndpoint.Status.ServiceAccount,
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
		Name:           cep.GetName(),
		Networking:     epNetworking,
		Encryption:     cep.Status.Encryption,
		IdentityID:     identityID,
		NamedPorts:     cep.Status.NamedPorts.DeepCopy(),
		ServiceAccount: cep.Status.ServiceAccount,
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
		Networking:     ccep.Networking,
		NamedPorts:     ccep.NamedPorts,
		ServiceAccount: ccep.ServiceAccount,
	}
}
