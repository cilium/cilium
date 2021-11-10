// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package watchers

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_cli "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
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

	// cesController watches for CiliumEndpoint changes, and accordingly updates CiliumEndpointSlices
	// CiliumEndpoint watcher notifies the cesController, if any CiliumEndpoint is Added
	// Updated or Deleted.
	cesController *ces.CiliumEndpointSliceController
)

// CiliumEndpointsSliceInit starts a CiliumEndpointWatcher and caches cesController locally.
func CiliumEndpointsSliceInit(ciliumNPClient cilium_cli.CiliumV2Interface,
	cbController *ces.CiliumEndpointSliceController) {
	cesController = cbController
	CiliumEndpointsInit(ciliumNPClient, wait.NeverStop)
}

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

		var cacheResourceHandler cache.ResourceEventHandlerFuncs

		// Register notification function only if CES feature is enabled.
		if option.Config.EnableCiliumEndpointSlice {
			cacheResourceHandler = cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					if cep := objToCiliumEndpoint(obj); cep != nil {
						endpointUpdated(cep)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					if oldCEP := objToCiliumEndpoint(oldObj); oldCEP != nil {
						if newCEP := objToCiliumEndpoint(newObj); newCEP != nil {
							if oldCEP.DeepEqual(newCEP) {
								return
							}
							endpointUpdated(newCEP)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					if cep := objToCiliumEndpoint(obj); cep != nil {
						endpointDeleted(cep)
					}
				},
			}
		}

		ciliumEndpointInformer := informer.NewInformerWithStore(
			cache.NewListWatchFromClient(ciliumNPClient.RESTClient(),
				cilium_api_v2.CEPPluralName, v1.NamespaceAll, fields.Everything()),
			&cilium_api_v2.CiliumEndpoint{},
			0,
			cacheResourceHandler,
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
				Identity:   concreteObj.Status.Identity,
				Networking: concreteObj.Status.Networking,
				NamedPorts: concreteObj.Status.NamedPorts,
				Encryption: concreteObj.Status.Encryption,
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
					Identity:   ciliumEndpoint.Status.Identity,
					Networking: ciliumEndpoint.Status.Networking,
					NamedPorts: ciliumEndpoint.Status.NamedPorts,
					Encryption: ciliumEndpoint.Status.Encryption,
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

func endpointUpdated(cep *cilium_api_v2.CiliumEndpoint) {
	if cep.Status.Networking == nil || cep.Status.Identity == nil || cep.GetName() == "" || cep.Namespace == "" {
		return
	}
	cesController.Manager.InsertCEPInCache(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
}

func endpointDeleted(cep *cilium_api_v2.CiliumEndpoint) {
	cesController.Manager.RemoveCEPFromCache(ces.GetCEPNameFromCCEP(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace), ces.DefaultCESSyncTime)
}

// objToCiliumEndpoint attempts to cast object to a CiliumEndpoint object
// and returns a deep copy if the cast succeeds. Otherwise, nil is returned.
func objToCiliumEndpoint(obj interface{}) *cilium_api_v2.CiliumEndpoint {
	cep, ok := obj.(*cilium_api_v2.CiliumEndpoint)
	if ok {
		return cep
	}
	deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		// Delete was not observed by the watcher but is
		// removed from kube-apiserver. This is the last
		// known state and the object no longer exists.
		cep, ok := deletedObj.Obj.(*cilium_api_v2.CiliumEndpoint)
		if ok {
			return cep
		}
	}
	log.WithField(logfields.Object, logfields.Repr(obj)).
		Warn("Ignoring invalid v2 CiliumEndpoint")
	return cep
}
