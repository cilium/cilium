// Copyright 2021 Authors of Cilium
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

func (c *serviceCacheSubscriber) OnAdd(obj *slim_corev1.Service) {
	log.WithField(logfields.ServiceName, obj.Name).Debugf("Received service addition %+v", obj)
	K8sSvcCache.UpdateService(obj, c.swgSvcs)
}
func (c *serviceCacheSubscriber) OnUpdate(oldObj, newObj *slim_corev1.Service) {
	log.WithField(logfields.ServiceName, newObj.Name).Debugf("Received service update %+v", newObj)
	K8sSvcCache.UpdateService(newObj, c.swgSvcs)
}
func (c *serviceCacheSubscriber) OnDelete(obj *slim_corev1.Service) {
	log.WithField(logfields.ServiceName, obj.Name).Debugf("Received service deletion %+v", obj)
	K8sSvcCache.DeleteService(obj, c.swgSvcs)
}
