// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
)

type endpointManager struct {
	informer   cache.Controller
	store      cache.Store
	maxRetries int
}

func newEndpointManager(maxRetries int) (*endpointManager, error) {
	manager := &endpointManager{
		maxRetries: maxRetries,
	}

	// setup store and informer only for endpoints having label cilium.io/ingress
	manager.store, manager.informer = informer.NewInformer(
		cache.NewFilteredListWatchFromClient(k8s.WatcherClient().CoreV1().RESTClient(), "endpoints",
			v1.NamespaceAll, func(options *metav1.ListOptions) {
				options.LabelSelector = ciliumIngressLabelKey
			}),
		&slim_corev1.Endpoints{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)

	go manager.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync ingress endpoint")
	}
	return manager, nil
}

// getByKey is a wrapper of Store.GetByKey but with concrete Endpoint object
func (em *endpointManager) getByKey(key string) (*slim_corev1.Endpoints, bool, error) {
	objFromCache, exists, err := em.store.GetByKey(key)
	if objFromCache == nil || !exists || err != nil {
		return nil, exists, err
	}

	endpoint, ok := objFromCache.(*slim_corev1.Endpoints)
	if !ok {
		return nil, exists, fmt.Errorf("unexpected type found in service cache: %T", objFromCache)
	}
	return endpoint, exists, err
}

func getEndpointsForIngress(ingress *slim_networkingv1.Ingress) *v1.Endpoints {
	return &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getServiceNameForIngress(ingress),
			Namespace: ingress.Namespace,
			Labels:    map[string]string{ciliumIngressLabelKey: "true"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: slim_networkingv1.SchemeGroupVersion.String(),
					Kind:       "Ingress",
					Name:       ingress.Name,
					UID:        ingress.UID,
				},
			},
		},
		Subsets: []v1.EndpointSubset{
			{
				// This dummy endpoint is required as agent refuses to push service entry
				// to the lb map when the service has no backends.
				// Related github issue https://github.com/cilium/cilium/issues/19262
				Addresses: []v1.EndpointAddress{{IP: "192.192.192.192"}}, // dummy
				Ports:     []v1.EndpointPort{{Port: 9999}},               //dummy
			},
		},
	}
}
