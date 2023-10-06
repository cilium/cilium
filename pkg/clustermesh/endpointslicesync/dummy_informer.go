// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"time"

	cache "k8s.io/client-go/tools/cache"
)

type dummyInformer struct {
	name string
}

func (i *dummyInformer) AddIndexers(indexers cache.Indexers) error {
	log.Errorf("called not implemented function %s.AddIndexers", i.name)
	return nil
}
func (i *dummyInformer) GetIndexer() cache.Indexer {
	log.Errorf("called not implemented function %s.GetIndexer", i.name)
	return nil
}
func (i *dummyInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, resyncPeriod time.Duration) (cache.ResourceEventHandlerRegistration, error) {
	log.Errorf("called not implemented function %s.AddEventHandlerWithResyncPeriod", i.name)
	return nil, nil
}
func (i *dummyInformer) RemoveEventHandler(handle cache.ResourceEventHandlerRegistration) error {
	log.Errorf("called not implemented function %s.RemoveEventHandler", i.name)
	return nil
}
func (i *dummyInformer) GetStore() cache.Store {
	log.Errorf("called not implemented function %s.GetStore", i.name)
	return nil
}
func (i *dummyInformer) GetController() cache.Controller {
	log.Errorf("called not implemented function %s.GetController", i.name)
	return nil
}
func (i *dummyInformer) Run(stopCh <-chan struct{}) {
	log.Errorf("called not implemented function %s.Run", i.name)
}
func (i *dummyInformer) LastSyncResourceVersion() string {
	log.Errorf("called not implemented function %s.LastSyncResourceVersion", i.name)
	return ""
}
func (i *dummyInformer) SetWatchErrorHandler(handler cache.WatchErrorHandler) error {
	log.Errorf("called not implemented function %s.SetWatchErrorHandler", i.name)
	return nil
}
func (i *dummyInformer) SetTransform(handler cache.TransformFunc) error {
	log.Errorf("called not implemented function %s.SetTransform", i.name)
	return nil
}
func (i *dummyInformer) IsStopped() bool {
	log.Errorf("called not implemented function %s.IsStopped", i.name)
	return false
}
