// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

const identityIndex = "identity"

var (
	errNoCE  = errors.New("object is not a *cilium_api_v2.CiliumEndpoint")
	indexers = cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		identityIndex:        identityIndexFunc,
	}

	// CiliumEndpointStore contains all CiliumEndpoint present in k8s.
	// Warning: The CiliumEndpoints stored in the cache are not intended to be
	// used for Update operations in k8s as some of its fields were are not
	// populated.
	CiliumEndpointStore cache.Indexer

	// CiliumEndpointsSynced is closed once the CiliumEndpointStore is synced
	// with k8s.
	CiliumEndpointsSynced = make(chan struct{})
	// once is used to make sure CiliumEndpointsInit is only setup once.
	once sync.Once
)

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
	return nil, fmt.Errorf("%w - found %T", errNoCE, obj)
}

// CiliumEndpointsInit starts a CiliumEndpointWatcher
func CiliumEndpointsInit(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
	once.Do(func() {
		CiliumEndpointStore = cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, indexers)

		ciliumEndpointInformer := informer.NewInformerWithStore(
			utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumEndpointList](clientset.CiliumV2().CiliumEndpoints("")),
			&cilium_api_v2.CiliumEndpoint{},
			0,
			cache.ResourceEventHandlerFuncs{},
			transformToCiliumEndpoint,
			CiliumEndpointStore,
		)

		wg.Add(1)
		go func() {
			defer wg.Done()
			ciliumEndpointInformer.Run(ctx.Done())
		}()

		cache.WaitForCacheSync(ctx.Done(), ciliumEndpointInformer.HasSynced)
		close(CiliumEndpointsSynced)
	})
}

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

// HasCE returns true or false if the Cilium Endpoint store has the endpoint
// with the given name.
func HasCE(ns, name string) (*cilium_api_v2.CiliumEndpoint, bool, error) {
	if CiliumEndpointStore == nil {
		return nil, false, nil
	}
	cepKey := fmt.Sprintf("%s/%s", ns, name)
	item, exists, err := CiliumEndpointStore.GetByKey(cepKey)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	cep := item.(*cilium_api_v2.CiliumEndpoint)
	return cep, exists, nil
}
