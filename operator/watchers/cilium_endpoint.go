// Copyright 2016-2020 Authors of Cilium
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

package watchers

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_cli "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/tools/cache"
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
func CiliumEndpointsInit(ciliumNPClient cilium_cli.CiliumV2Interface, stopCh <-chan struct{}) {
	once.Do(func() {
		CiliumEndpointStore = cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, indexers)

		ciliumEndpointInformer := informer.NewInformerWithStore(
			cache.NewListWatchFromClient(ciliumNPClient.RESTClient(),
				cilium_api_v2.CEPPluralName, v1.NamespaceAll, fields.Everything()),
			&cilium_api_v2.CiliumEndpoint{},
			0,
			cache.ResourceEventHandlerFuncs{},
			convertToCiliumEndpoint,
			CiliumEndpointStore,
		)
		go ciliumEndpointInformer.Run(stopCh)

		cache.WaitForCacheSync(stopCh, ciliumEndpointInformer.HasSynced)
		close(CiliumEndpointsSynced)
	})
}

// convertToCiliumEndpoint converts a CiliumEndpoint to a minimal CiliumEndpoint
// containing only a minimal set of entities used to identity a CiliumEndpoint
// Warning: The CiliumEndpoints created by the converter are not intended to be
// used for Update operations in k8s.
func convertToCiliumEndpoint(obj interface{}) interface{} {
	switch concreteObj := obj.(type) {
	case *cilium_api_v2.CiliumEndpoint:
		p := &cilium_api_v2.CiliumEndpoint{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: metav1.ObjectMeta{
				Name:            concreteObj.Name,
				Namespace:       concreteObj.Namespace,
				ResourceVersion: concreteObj.ResourceVersion,
				OwnerReferences: concreteObj.OwnerReferences,
			},
			Status: cilium_api_v2.EndpointStatus{
				Identity: concreteObj.Status.Identity,
			},
		}
		*concreteObj = cilium_api_v2.CiliumEndpoint{}
		return p
	case cache.DeletedFinalStateUnknown:
		ciliumEndpoint, ok := concreteObj.Obj.(*cilium_api_v2.CiliumEndpoint)
		if !ok {
			return obj
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
				},
				Status: cilium_api_v2.EndpointStatus{
					Identity: ciliumEndpoint.Status.Identity,
				},
			},
		}
		// Small GC optimization
		*ciliumEndpoint = cilium_api_v2.CiliumEndpoint{}
		return dfsu
	default:
		return obj
	}
}

// HasCEWithIdentity returns true or false if the Cilium Endpoint store has
// the given identity.
func HasCEWithIdentity(identity string) bool {
	if CiliumEndpointStore == nil {
		return false
	}
	ces, _ := CiliumEndpointStore.IndexKeys(identityIndex, identity)

	return len(ces) != 0
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
