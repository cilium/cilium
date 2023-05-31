// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// transformToCiliumEndpoint transforms a CiliumEndpoint to a minimal CiliumEndpoint
// containing only a minimal set of entities used to identity a CiliumEndpoint
// Warning: The CiliumEndpoints created by the converter are not intended to be
// used for Update operations in k8s. If the given obj can't be cast into either
// CiliumEndpoint nor DeletedFinalStateUnknown, an error is returned.
func transformToCiliumEndpoint(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *cilium_api_v2.CiliumEndpoint:
		p := &cilium_api_v2.CiliumEndpoint{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
				OwnerReferences: concreteObj.OwnerReferences,
				UID:             concreteObj.UID,
			},
			Status: cilium_api_v2.EndpointStatus{
				Identity:   concreteObj.Status.Identity,
				Networking: concreteObj.Status.Networking,
				NamedPorts: concreteObj.Status.NamedPorts,
				Encryption: concreteObj.Status.Encryption,
			},
		}
		*concreteObj = cilium_api_v2.CiliumEndpoint{}
		return p, nil
	case cache.DeletedFinalStateUnknown:
		ciliumEndpoint, ok := concreteObj.Obj.(*cilium_api_v2.CiliumEndpoint)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &cilium_api_v2.CiliumEndpoint{
				TypeMeta: ciliumEndpoint.TypeMeta,
				ObjectMeta: metav1.ObjectMeta{
					Name:            ciliumEndpoint.Name,
					Namespace:       ciliumEndpoint.Namespace,
					ResourceVersion: ciliumEndpoint.ResourceVersion,
					OwnerReferences: ciliumEndpoint.OwnerReferences,
					UID:             ciliumEndpoint.UID,
				},
				Status: cilium_api_v2.EndpointStatus{
					Identity:   ciliumEndpoint.Status.Identity,
					Networking: ciliumEndpoint.Status.Networking,
					NamedPorts: ciliumEndpoint.Status.NamedPorts,
					Encryption: ciliumEndpoint.Status.Encryption,
				},
			},
		}
		// Small GC optimization
		*ciliumEndpoint = cilium_api_v2.CiliumEndpoint{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

const identityIndex = "identity"

// identityIndexFunc index identities by ID.
func identityIndexFunc(obj interface{}) ([]string, error) {
	switch t := obj.(type) {
	case *cilium_api_v2.CiliumEndpoint:
		if t.Status.Identity != nil {
			id := strconv.FormatInt(t.Status.Identity.ID, 10)
			return []string{id}, nil
		}
		return []string{"0"}, nil
	}
	return nil, fmt.Errorf("object is not a *cilium_api_v2.CiliumEndpoint - found %T", obj)
}
