// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type envoyConfigManager struct {
	client     client.Clientset
	informer   cache.Controller
	store      cache.Store
	maxRetries int
}

func newEnvoyConfigManager(client client.Clientset, maxRetries int) (*envoyConfigManager, error) {
	manager := &envoyConfigManager{
		client:     client,
		maxRetries: maxRetries,
	}

	manager.store, manager.informer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2.CiliumEnvoyConfigList](client.CiliumV2().CiliumEnvoyConfigs(corev1.NamespaceAll)),
		&v2.CiliumEnvoyConfig{},
		0,
		cache.ResourceEventHandlerFuncs{},
		nil,
	)

	go manager.informer.Run(wait.NeverStop)
	if !cache.WaitForCacheSync(wait.NeverStop, manager.informer.HasSynced) {
		return manager, fmt.Errorf("unable to sync envoy configs")
	}
	return manager, nil
}

// getByKey is a wrapper of Store.GetByKey but with concrete CiliumEnvoyConfig object
func (em *envoyConfigManager) getByKey(key string) (*v2.CiliumEnvoyConfig, bool, error) {
	objFromCache, exists, err := em.store.GetByKey(key)
	if objFromCache == nil || !exists || err != nil {
		return nil, exists, err
	}
	envoyConfig, ok := objFromCache.(*v2.CiliumEnvoyConfig)
	if !ok {
		return nil, exists, fmt.Errorf("got invalid object from cache")
	}
	return envoyConfig, exists, err
}

func (em *envoyConfigManager) MarkSynced() {
	em.informer.HasSynced()
}
