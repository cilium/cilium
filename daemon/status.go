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
	"sort"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
	k8sTypes "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// collectStatusInterval is how often statuses will be collected internally
	collectStatusInterval = 5 * time.Second

	// staleTimeout is how old a status can be before we report it as stale
	staleTimeout = 2 * collectStatusInterval
)

type getHealthz struct {
	daemon *Daemon
}

func NewGetHealthzHandler(d *Daemon) GetHealthzHandler {
	return &getHealthz{daemon: d}
}

func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	d := h.daemon
	sr := d.daemonStatus.getStatus()
	return NewGetHealthzOK().WithPayload(&sr)
}

var collectors = []struct {
	name        string
	collectFunc func(dss *daemonStatus, d *Daemon) error
}{
	{
		name: "kvstore-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			var kvStoreStatus *models.Status
			if info, err := kvstore.Client().Status(); err != nil {
				kvStoreStatus = &models.Status{State: models.StatusStateFailure, Msg: fmt.Sprintf("Err: %s - %s", err, info)}
			} else {
				kvStoreStatus = &models.Status{State: models.StatusStateOk, Msg: info}
			}

			dss.Lock()
			defer dss.Unlock()
			dss.kvStoreStatus = kvStoreStatus
			dss.kvStoreStatusTS = time.Now()

			return nil
		}},

	{
		name: "k8s-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			k8sStatus := d.getK8sStatus()

			dss.Lock()
			defer dss.Unlock()
			dss.k8sStatus = k8sStatus
			dss.k8sStatusTS = time.Now()

			return nil
		}},

	{
		name: "controller-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			controllerStatus := controller.GetGlobalStatus()

			dss.Lock()
			defer dss.Unlock()
			dss.controllerStatus = controllerStatus
			dss.controllerStatusTS = time.Now()

			return nil
		}},

	{
		name: "container-runtime-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			containerRuntimeStatus := containerd.Status()

			dss.Lock()
			defer dss.Unlock()
			dss.containerRuntimeStatus = containerRuntimeStatus
			dss.containerRuntimeStatusTS = time.Now()

			return nil
		}},

	{
		name: "global-locks-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			d.checkLocks()

			dss.Lock()
			defer dss.Unlock()
			dss.lockStatusTS = time.Now()

			return nil
		}},

	{
		name: "ipam-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			var ipamStatus *models.IPAMStatus
			if d.DebugEnabled() {
				ipamStatus = d.DumpIPAM()
			}

			dss.Lock()
			defer dss.Unlock()
			dss.ipamStatus = ipamStatus
			dss.ipamStatusTS = time.Now()

			return nil
		}},

	{
		name: "node-monitor-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			nodeMonitorStatus := d.nodeMonitor.State()

			dss.Lock()
			defer dss.Unlock()
			dss.nodeMonitorStatus = nodeMonitorStatus
			dss.nodeMonitorStatusTS = time.Now()

			return nil
		}},

	{
		name: "cluster-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			clusterStatus := d.getNodeStatus()

			dss.Lock()
			defer dss.Unlock()
			dss.clusterStatus = clusterStatus
			dss.clusterStatusTS = time.Now()

			return nil
		}},

	{
		name: "cilium-health-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			var ciliumHealthStatus *models.Status
			if d.ciliumHealth != nil {
				ciliumHealthStatus = d.ciliumHealth.GetStatus()
			}

			dss.Lock()
			defer dss.Unlock()
			dss.healthStatus = ciliumHealthStatus
			dss.healthStatusTS = time.Now()

			return nil
		}},

	{
		name: "l7Proxy-status-collector",
		collectFunc: func(dss *daemonStatus, d *Daemon) error {
			var l7ProxyStatus *models.ProxyStatus
			if d.l7Proxy != nil {
				l7ProxyStatus = d.l7Proxy.GetStatusModel()
			}

			dss.Lock()
			defer dss.Unlock()
			dss.l7ProxyStatus = l7ProxyStatus
			dss.l7ProxyStatusTS = time.Now()

			return nil
		}},
}

// daemonStatus is a simple holder of collected statuses.
type daemonStatus struct {
	lock.RWMutex

	// controllers needs a write lock when updating controllers
	controllers controller.Manager

	// the most recently collected status per subsystem
	controllerStatus       models.ControllerStatuses
	kvStoreStatus          *models.Status
	containerRuntimeStatus *models.Status
	k8sStatus              *models.K8sStatus
	ipamStatus             *models.IPAMStatus
	nodeMonitorStatus      *models.MonitorStatus
	clusterStatus          *models.ClusterStatus
	healthStatus           *models.Status
	l7ProxyStatus          *models.ProxyStatus

	// the timestamp when each corresponding status was collected
	controllerStatusTS       time.Time
	lockStatusTS             time.Time
	kvStoreStatusTS          time.Time
	containerRuntimeStatusTS time.Time
	k8sStatusTS              time.Time
	ipamStatusTS             time.Time
	nodeMonitorStatusTS      time.Time
	clusterStatusTS          time.Time
	healthStatusTS           time.Time
	l7ProxyStatusTS          time.Time
}

// startStatusCollector spawns all the controllers used to collect subsystem
// statuses for a daemon object d
func (dss *daemonStatus) startStatusCollector(d *Daemon) {
	dss.Lock()
	defer dss.Unlock()

	for i := range collectors {
		collector := collectors[i]
		dss.controllers.UpdateController(collector.name,
			controller.ControllerParams{
				RunInterval: collectStatusInterval,
				DoFunc:      func() error { return collector.collectFunc(dss, d) },
			})
	}
}

// getStatus constructs a /healthz response from the asynchronously collected
// subsystem statuses. It checks for certain error states and reports this in
// the global status field.
func (dss *daemonStatus) getStatus() models.StatusResponse {
	dss.RLock()
	defer dss.RUnlock()

	sr := models.StatusResponse{
		Controllers:      dss.controllerStatus,
		Kubernetes:       dss.k8sStatus,
		ContainerRuntime: dss.containerRuntimeStatus,
		Kvstore:          dss.kvStoreStatus,
		IPAM:             dss.ipamStatus, // this can be nil
		NodeMonitor:      dss.nodeMonitorStatus,
		Cluster:          dss.clusterStatus,
		Proxy:            dss.l7ProxyStatus,
	}

	stale, oldestTimestamp := dss.getStaleComponents()
	switch {
	case len(stale) > 0:
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   fmt.Sprintf("Stale status (oldest since %v) in subsystem(s): %s", oldestTimestamp, strings.Join(stale, ", ")),
		}

	case sr.Kvstore == nil || sr.Kvstore.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: sr.Kvstore.State,
			Msg:   "Kvstore service is not ready",
		}

	case sr.ContainerRuntime == nil || sr.ContainerRuntime.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: sr.ContainerRuntime.State,
			Msg:   "Container runtime is not ready",
		}

	case k8s.IsEnabled() &&
		(sr.Kubernetes == nil || sr.Kubernetes.State != models.StatusStateOk):
		sr.Cilium = &models.Status{
			State: sr.Kubernetes.State,
			Msg:   "Kubernetes service is not ready",
		}

	default:
		sr.Cilium = &models.Status{State: models.StatusStateOk, Msg: "OK"}
	}

	return sr
}

// getStaleComponents checks for timestamps that are older than staleTimeout
func (dss *daemonStatus) getStaleComponents() (stale []string, oldest time.Time) {
	var (
		staleThreshold = time.Now().Add(-1 * staleTimeout) // timestamps older than this are stale

		timestamps = map[string]time.Time{
			"global-locks":      dss.lockStatusTS,
			"controller":        dss.controllerStatusTS,
			"kvstore":           dss.kvStoreStatusTS,
			"container-runtime": dss.containerRuntimeStatusTS,
			"k8s":               dss.k8sStatusTS,
			"ipam":              dss.ipamStatusTS,
			"node-monitor":      dss.nodeMonitorStatusTS,
			"cluster-status":    dss.clusterStatusTS,
			"cilium-health":     dss.healthStatusTS,
			"l7-proxy":          dss.l7ProxyStatusTS}
	)

	for system, ts := range timestamps {
		switch {
		// treat no-data as staler than anything else, then update the list
		case ts.IsZero():
			stale = append(stale, system)
			oldest = ts

		// this timestamp is old enough to be stale
		case !ts.IsZero() && ts.Before(staleThreshold):
			stale = append(stale, system)
			// accumulate the oldest timestamp
			if ts.Before(oldest) {
				oldest = ts
			}
		}
	}

	sort.Strings(stale) // avoid the map's random order
	return stale, oldest
}

// getK8sStatus synchronously builds the k8s status
func (d *Daemon) getK8sStatus() *models.K8sStatus {
	if !k8s.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}

	}

	var (
		k8sStatus *models.K8sStatus
		status    *k8sTypes.ComponentStatus
		err       error
	)
	if status, err = k8s.Client().CoreV1().ComponentStatuses().Get("controller-manager", metav1.GetOptions{}); err != nil {
		return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
	}
	switch {
	case len(status.Conditions) == 0:
		k8sStatus = &models.K8sStatus{
			State: models.StatusStateWarning,
			Msg:   "Unable to retrieve controller-manager's kubernetes status",
		}
	case status.Conditions[0].Status == k8sTypes.ConditionTrue:
		k8sStatus = &models.K8sStatus{
			State: models.StatusStateOk,
			Msg:   "OK",
		}
	default:
		k8sStatus = &models.K8sStatus{
			State: models.StatusStateFailure,
			Msg:   status.Conditions[0].Message,
		}
	}

	k8sStatus.K8sAPIVersions = d.k8sAPIGroups.getGroups()

	return k8sStatus
}

func (d *Daemon) checkLocks() {
	// Try to acquire a couple of global locks to have the status API fail
	// in case of a deadlock on these locks

	option.Config.ConfigPatchMutex.Lock()
	option.Config.ConfigPatchMutex.Unlock()

	d.GetCompilationLock().Lock()
	d.GetCompilationLock().Unlock()
}

func (d *Daemon) getNodeStatus() *models.ClusterStatus {
	ipv4 := !option.Config.IPv4Disabled

	local, _ := node.GetLocalNode()
	clusterStatus := models.ClusterStatus{
		Self: local.Name,
	}
	for _, node := range node.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel(ipv4))
	}
	return &clusterStatus
}
