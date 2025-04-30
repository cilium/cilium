// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/client-go/tools/cache"
)

type dummyInformer struct {
	name   string
	logger *slog.Logger
}

func (i *dummyInformer) AddIndexers(indexers cache.Indexers) error {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.AddIndexers", i.name))
	return nil
}
func (i *dummyInformer) GetIndexer() cache.Indexer {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.GetIndexer", i.name))
	return nil
}
func (i *dummyInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, resyncPeriod time.Duration) (cache.ResourceEventHandlerRegistration, error) {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.AddEventHandlerWithResyncPeriod", i.name))
	return nil, nil
}
func (i *dummyInformer) AddEventHandlerWithOptions(handler cache.ResourceEventHandler, options cache.HandlerOptions) (cache.ResourceEventHandlerRegistration, error) {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.AddEventHandlerWithResyncPeriod", i.name))
	return nil, nil
}
func (i *dummyInformer) RemoveEventHandler(handle cache.ResourceEventHandlerRegistration) error {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.RemoveEventHandler", i.name))
	return nil
}
func (i *dummyInformer) GetStore() cache.Store {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.GetStore", i.name))
	return nil
}
func (i *dummyInformer) GetController() cache.Controller {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.GetController", i.name))
	return nil
}
func (i *dummyInformer) Run(stopCh <-chan struct{}) {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.Run", i.name))
}
func (i *dummyInformer) RunWithContext(ctx context.Context) {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.RunWithContext", i.name))
}
func (i *dummyInformer) LastSyncResourceVersion() string {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.LastSyncResourceVersion", i.name))
	return ""
}
func (i *dummyInformer) SetWatchErrorHandler(handler cache.WatchErrorHandler) error {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.SetWatchErrorHandler", i.name))
	return nil
}
func (i *dummyInformer) SetWatchErrorHandlerWithContext(handler cache.WatchErrorHandlerWithContext) error {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.SetWatchErrorHandlerWithContext", i.name))
	return nil
}
func (i *dummyInformer) SetTransform(handler cache.TransformFunc) error {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.SetTransform", i.name))
	return nil
}
func (i *dummyInformer) IsStopped() bool {
	i.logger.Error(fmt.Sprintf("called not implemented function %s.IsStopped", i.name))
	return false
}
