// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"reflect"
	"sync/atomic"

	"go.universe.tf/metallb/pkg/allocator"
	"go.universe.tf/metallb/pkg/config"
	"go.universe.tf/metallb/pkg/k8s/types"

	"github.com/go-kit/kit/log"
	v1 "k8s.io/api/core/v1"
)

type Controller struct {
	Client service
	IPs    *allocator.Allocator

	synced uint32
	config *config.Config
}

func (c *Controller) SetBalancer(l log.Logger, name string, svcRo *v1.Service, _ *v1.Endpoints) types.SyncState {
	l.Log("event", "startUpdate", "msg", "start of service update")
	defer l.Log("event", "endUpdate", "msg", "end of service update")

	if svcRo == nil {
		c.deleteBalancer(l, name)
		// There might be other LBs stuck waiting for an IP, so when
		// we delete a balancer we should reprocess all of them to
		// check for newly feasible balancers.
		return types.SyncStateReprocessAll
	}

	if c.config == nil {
		// Config hasn't been read, nothing we can do just yet.
		l.Log("event", "noConfig", "msg", "not processing, still waiting for config")
		return types.SyncStateSuccess
	}

	// Making a copy unconditionally is a bit wasteful, since we don't
	// always need to update the service. But, making an unconditional
	// copy makes the code much easier to follow, and we have a GC for
	// a reason.
	svc := svcRo.DeepCopy()
	if !c.convergeBalancer(l, name, svc) {
		return types.SyncStateError
	}
	if reflect.DeepEqual(svcRo, svc) {
		l.Log("event", "noChange", "msg", "service converged, no change")
		return types.SyncStateSuccess
	}

	if !reflect.DeepEqual(svcRo.Status, svc.Status) {
		var st v1.ServiceStatus
		st, svc = svc.Status, svcRo.DeepCopy()
		svc.Status = st
		if err := c.Client.UpdateStatus(svc); err != nil {
			l.Log("op", "updateServiceStatus", "error", err, "msg", "failed to update service status")
			return types.SyncStateError
		}
	}
	l.Log("event", "serviceUpdated", "msg", "updated service object")

	return types.SyncStateSuccess
}

func (c *Controller) deleteBalancer(l log.Logger, name string) {
	if c.IPs.Unassign(name) {
		l.Log("event", "serviceDeleted", "msg", "service deleted")
	}
}

func (c *Controller) SetConfig(l log.Logger, cfg *config.Config) types.SyncState {
	l.Log("event", "startUpdate", "msg", "start of config update")
	defer l.Log("event", "endUpdate", "msg", "end of config update")

	if cfg == nil {
		l.Log("op", "setConfig", "error", "no MetalLB configuration in cluster", "msg", "configuration is missing, MetalLB will not function")
		return types.SyncStateError
	}

	if err := c.IPs.SetPools(cfg.Pools); err != nil {
		l.Log("op", "setConfig", "error", err, "msg", "applying new configuration failed")
		return types.SyncStateError
	}
	c.config = cfg
	return types.SyncStateReprocessAll
}

func (c *Controller) MarkSynced(l log.Logger) {
	atomic.StoreUint32(&c.synced, 1)
	l.Log("event", "stateSynced", "msg", "controller synced, can allocate IPs now")
}

// Service offers methods to mutate a Kubernetes service object.
type service interface {
	UpdateStatus(svc *v1.Service) error
	Infof(svc *v1.Service, desc, msg string, args ...interface{})
	Errorf(svc *v1.Service, desc, msg string, args ...interface{})
}
