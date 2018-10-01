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

var (
	collector *agentStatusCollector
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

func (d *Daemon) getNodeStatus() *models.ClusterStatus {
	ipv4 := !option.Config.IPv4Disabled

	clusterStatus := models.ClusterStatus{
		Self: node.GetLocalNode().Fullname(),
	}
	for _, node := range node.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel(ipv4))
	}
	return &clusterStatus
}

func (d *Daemon) startStatusCollector() {
	collector = d.newAgentStatusCollector()
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

type agentStatusCollector struct {
	mutex     lock.Mutex
	resp      models.StatusResponse
	daemon    *Daemon
	collector *status.Collector
}

func toModelStatus(status status.Status) *models.Status {
	switch {
	case status.StaleWarning:
		return &models.Status{State: models.StatusStateWarning, Msg: err.Error()}
	case status.Err != nil:
		return &models.Status{State: models.StatusStateFailure, Msg: err.Error()}
	default:
		return &models.Status{State: models.StatusStateOk, Msg: status.Data.(string)}
	}
}

func (d *Daemon) newAgentStatusCollector() *agentStatusCollector {
	a := &agentStatusCollector{}

	probes := []status.Probe{
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				// Try to acquire a couple of global locks to have the status API fail
				// in case of a deadlock on these locks
				option.Config.ConfigPatchMutex.Lock()
				option.Config.ConfigPatchMutex.Unlock()
				return nil, nil
			},
			Status: func(status status.Status) {
				a.mutex.Lock()
				switch {
				case status.Err != nil:
					a.response.Stale["check-locks"] = status.Err.Error()
				default:
					delete(a.response.Stale, "check-locks")
				}
				a.mutex.Unlock()
			},
		},
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				return kvstore.Client().Status()
			},
			Status: func(status status.Status) {
				a.mutex.Lock()
				s.response.Kvstore = toModelStatus(status)
				a.mutex.Unlock()
			},
		},
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				status := d.getK8sStatus()
				return status, nil
			},
			Status: func(status status.Status) {
				a.mutex.Lock()
				switch {
				case status.StaleWarning:
					s.response.Kvstore = &models.Status{State: models.StatusStateWarning, Msg: err.Error()}
				case status.Err != nil:
					s.response.Kvstore = &models.Status{State: models.StatusStateFailure, Msg: err.Error()}
				default:
					s.response.Kvstore = &models.Status{State: models.StatusStateOk, Msg: status.Data.(string)}
				}
				a.mutex.Unlock()
			},
		},
		{
			Probe: func(ctx context.Context) (interface{}, error) {
				status := controller.GetGlobalStatus()
				return status, nil
			},
			Status: func(status status.Status) {
				a.mutex.Lock()
				switch {
				case status.StaleWarning:
					s.response.Kvstore = &models.Status{State: models.StatusStateWarning, Msg: err.Error()}
				case status.Err != nil:
					s.response.Kvstore = &models.Status{State: models.StatusStateFailure, Msg: err.Error()}
				default:
					s.response.Controllers = GetGlobalStatus()
				}
				a.mutex.Unlock()
			},
		},
	}

	a.collector = status.NewCollector(probes, Configuration{
		Interval:         5 * time.Second,
		WarningThreshold: 15 * time.Second,
		FailureThreshold: time.Minute,
	})

	controller.NewManager().UpdateController("agent-status",
		controller.ControllerParams{
			DoFunc: func() error {
				d.statusCollectMutex.Lock()
				d.statusResponse = response
				d.statusResponseTimestamp = time.Now()
				d.statusCollectMutex.Unlock()

				return nil
			},
			RunInterval: time.Second,
		})

	return a
}

func (s *agentStatusCollector) k8sStatus(ctx context.Context) {

	s.mutex.Lock()
	s.response.Kubernetes = status
	s.mutex.Unlock()
}

func (s *agentStatusCollector) Tests() status.FunctionMap {
}

func (d *Daemon) getStatus() models.StatusResponse {

	sr.ContainerRuntime = workloads.Status()

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
