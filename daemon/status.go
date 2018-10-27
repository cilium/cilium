// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
)

const (
	collectStatusInterval = 5 * time.Second

	// status data older than staleTimeout triggers the stale warning
	staleTimeout = 1 * time.Minute
)

func (d *Daemon) getK8sStatus() *models.K8sStatus {
	if !k8s.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}

	}

	version, err := k8s.Client().Discovery().ServerVersion()
	if err != nil {
		return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
	}

	k8sStatus := &models.K8sStatus{
		State:          models.StatusStateOk,
		Msg:            fmt.Sprintf("%s.%s (%s) [%s]", version.Major, version.Minor, version.GitVersion, version.Platform),
		K8sAPIVersions: d.k8sAPIGroups.getGroups(),
	}

	return k8sStatus
}

type getHealthz struct {
	daemon *Daemon
}

func NewGetHealthzHandler(d *Daemon) GetHealthzHandler {
	return &getHealthz{daemon: d}
}

func checkLocks(d *Daemon) {
	// Try to acquire a couple of global locks to have the status API fail
	// in case of a deadlock on these locks

	option.Config.ConfigPatchMutex.Lock()
	option.Config.ConfigPatchMutex.Unlock()
}

func (d *Daemon) getNodeStatus() *models.ClusterStatus {
	ipv4 := option.Config.EnableIPv4

	clusterStatus := models.ClusterStatus{
		Self: node.GetLocalNode().Fullname(),
	}
	for _, node := range node.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel(ipv4))
	}
	return &clusterStatus
}

func (d *Daemon) collectStatus() {
	for {
		response := d.getStatus()

		d.statusCollectMutex.Lock()
		d.statusResponse = response
		d.statusResponseTimestamp = time.Now()
		d.statusCollectMutex.Unlock()

		time.Sleep(collectStatusInterval)
	}
}

func (d *Daemon) startStatusCollector() {
	go d.collectStatus()
}

func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	d := h.daemon
	d.statusCollectMutex.RLock()
	sr := d.statusResponse
	timestamp := d.statusResponseTimestamp
	d.statusCollectMutex.RUnlock()

	if time.Since(timestamp) > staleTimeout {
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   fmt.Sprintf("Stale status data (since %v)", timestamp),
		}
	}

	return NewGetHealthzOK().WithPayload(&sr)
}

func (d *Daemon) getStatus() models.StatusResponse {
	sr := models.StatusResponse{
		Controllers: controller.GetGlobalStatus(),
	}

	checkLocks(d)

	if info, err := kvstore.Client().Status(); err != nil {
		sr.Kvstore = &models.Status{State: models.StatusStateFailure, Msg: fmt.Sprintf("Err: %s - %s", err, info)}
	} else {
		sr.Kvstore = &models.Status{State: models.StatusStateOk, Msg: info}
	}

	sr.ContainerRuntime = workloads.Status()

	sr.Kubernetes = d.getK8sStatus()

	// Note: A final, overriding, check is made in Handle to check the staleness
	// of this data, and will clobber these messages if set.
	if sr.Kvstore.State != models.StatusStateOk {
		sr.Cilium = &models.Status{
			State: sr.Kvstore.State,
			Msg:   "Kvstore service is not ready",
		}
	} else if sr.ContainerRuntime.State != models.StatusStateOk {
		sr.Cilium = &models.Status{
			State: sr.ContainerRuntime.State,
			Msg:   "Container runtime is not ready",
		}
	} else if k8s.IsEnabled() && sr.Kubernetes.State != models.StatusStateOk {
		sr.Cilium = &models.Status{
			State: sr.Kubernetes.State,
			Msg:   "Kubernetes service is not ready",
		}
	} else {
		sr.Cilium = &models.Status{State: models.StatusStateOk, Msg: "OK"}
	}

	sr.IPAM = d.DumpIPAM()
	sr.NodeMonitor = d.nodeMonitor.State()

	sr.Cluster = d.getNodeStatus()

	if d.ciliumHealth != nil {
		sr.Cluster.CiliumHealth = d.ciliumHealth.GetStatus()
	}

	if d.l7Proxy != nil {
		sr.Proxy = d.l7Proxy.GetStatusModel()
	}

	return sr
}
