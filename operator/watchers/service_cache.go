// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package watchers

import (
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func newServiceCacheSubscriber(swgSvcs, swgEps *lock.StoppableWaitGroup) *serviceCacheSubscriber {
	return &serviceCacheSubscriber{
		swgSvcs: swgSvcs,
		swgEps:  swgEps,
	}
}

// serviceCacheSubscriber represents an object that's subscribed to K8s service
// events in order to keep the K8sSvcCache up-to-date. It implements
// subscriber.ServiceHandler and is used in the watcher.
type serviceCacheSubscriber struct {
	swgSvcs, swgEps *lock.StoppableWaitGroup
}

func (c *serviceCacheSubscriber) OnAddService(obj *slim_corev1.Service) error {
	log.WithField(logfields.ServiceName, obj.Name).Debugf("Received service addition %+v", obj)
	K8sSvcCache.UpdateService(obj, c.swgSvcs)
	return nil
}
func (c *serviceCacheSubscriber) OnUpdateService(oldObj, newObj *slim_corev1.Service) error {
	log.WithField(logfields.ServiceName, newObj.Name).Debugf("Received service update %+v", newObj)
	K8sSvcCache.UpdateService(newObj, c.swgSvcs)
	return nil
}
func (c *serviceCacheSubscriber) OnDeleteService(obj *slim_corev1.Service) error {
	log.WithField(logfields.ServiceName, obj.Name).Debugf("Received service deletion %+v", obj)
	K8sSvcCache.DeleteService(obj, c.swgSvcs)
	return nil
}
