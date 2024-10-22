// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"time"

	"github.com/sirupsen/logrus"
	cache "k8s.io/client-go/tools/cache"
)

type dummyInformer struct {
	name   string
	logger logrus.FieldLogger
}

func (i *dummyInformer) AddIndexers(indexers cache.Indexers) error {
	i.logger.Errorf("called not implemented function %s.AddIndexers", i.name)
	return nil
}
func (i *dummyInformer) GetIndexer() cache.Indexer {
	i.logger.Errorf("called not implemented function %s.GetIndexer", i.name)
	return nil
}
func (i *dummyInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, resyncPeriod time.Duration) (cache.ResourceEventHandlerRegistration, error) {
	i.logger.Errorf("called not implemented function %s.AddEventHandlerWithResyncPeriod", i.name)
	return nil, nil
}
func (i *dummyInformer) RemoveEventHandler(handle cache.ResourceEventHandlerRegistration) error {
	i.logger.Errorf("called not implemented function %s.RemoveEventHandler", i.name)
	return nil
}
func (i *dummyInformer) GetStore() cache.Store {
	i.logger.Errorf("called not implemented function %s.GetStore", i.name)
	return nil
}
func (i *dummyInformer) GetController() cache.Controller {
	i.logger.Errorf("called not implemented function %s.GetController", i.name)
	return nil
}
func (i *dummyInformer) Run(stopCh <-chan struct{}) {
	i.logger.Errorf("called not implemented function %s.Run", i.name)
}
func (i *dummyInformer) LastSyncResourceVersion() string {
	i.logger.Errorf("called not implemented function %s.LastSyncResourceVersion", i.name)
	return ""
}
func (i *dummyInformer) SetWatchErrorHandler(handler cache.WatchErrorHandler) error {
	i.logger.Errorf("called not implemented function %s.SetWatchErrorHandler", i.name)
	return nil
}
func (i *dummyInformer) SetTransform(handler cache.TransformFunc) error {
	i.logger.Errorf("called not implemented function %s.SetTransform", i.name)
	return nil
}
func (i *dummyInformer) IsStopped() bool {
	i.logger.Errorf("called not implemented function %s.IsStopped", i.name)
	return false
}
