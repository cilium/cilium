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
	"github.com/cilium/cilium/pkg/bgp/manager"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
)

// StartLBIPAllocator starts the service watcher if it hasn't already and looks
// for service of type LoadBalancer. Once it finds a service of that type, it
// will try to allocate an external IP (LoadBalancerIP) for it.
func StartLBIPAllocator(cfg ServiceSyncConfiguration) {
	optsModifier, err := utils.GetServiceListOptionsModifier(cfg)
	if err != nil {
		log.WithError(err).Fatal("Error creating service option modifier")
	}

	swgSvcs := lock.NewStoppableWaitGroup()
	swgEps := lock.NewStoppableWaitGroup()
	InitServiceWatcher(cfg, swgSvcs, swgEps, optsModifier)

	m := manager.New(serviceIndexer)
	serviceSubscribers.Register(m)

	go func() {
		<-k8sSvcCacheSynced
		m.MarkSynced(m.Logger())
	}()
}
