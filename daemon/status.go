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
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
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
	ipv4 := !option.Config.IPv4Disabled

	clusterStatus := models.ClusterStatus{
		Self: node.GetLocalNode().Fullname(),
	}
	for _, node := range node.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel(ipv4))
	}
	return &clusterStatus
}

func (h *getHealthz) Handle(params GetHealthzParams) middleware.Responder {
	sr := h.daemon.getStatus()

	return NewGetHealthzOK().WithPayload(&sr)
}

func (d *Daemon) getStatus() models.StatusResponse {
	staleProbes := d.statusCollector.GetStaleProbes()
	stale := make(map[string]strfmt.DateTime, len(staleProbes))
	for probe, startTime := range staleProbes {
		stale[probe] = strfmt.DateTime(startTime)
	}

	d.statusCollectMutex.RLock()
	defer d.statusCollectMutex.RUnlock()

	sr := d.statusResponse
	sr.Stale = stale

	switch {
	case len(sr.Stale) > 0:
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   "Stale status data",
		}
	case sr.Kvstore != nil && sr.Kvstore.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: sr.Kvstore.State,
			Msg:   "Kvstore service is not ready",
		}
	case sr.ContainerRuntime != nil && sr.ContainerRuntime.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: sr.ContainerRuntime.State,
			Msg:   "Container runtime is not ready",
		}
	case k8s.IsEnabled() && sr.Kubernetes != nil && sr.Kubernetes.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: sr.Kubernetes.State,
			Msg:   "Kubernetes service is not ready",
		}
	default:
		sr.Cilium = &models.Status{State: models.StatusStateOk, Msg: "OK"}
	}

	return sr
}

func (d *Daemon) startStatusCollector() {
	probes := []status.Probe{
		{
			Name: "check-locks",
			Probe: func(ctx context.Context) (interface{}, error) {
				// Try to acquire a couple of global locks to have the status API fail
				// in case of a deadlock on these locks
				option.Config.ConfigPatchMutex.Lock()
				option.Config.ConfigPatchMutex.Unlock()
				return nil, nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()
				// FIXME we have no field for the lock status
			},
		},
		{
			Name: "kvstore",
			Probe: func(ctx context.Context) (interface{}, error) {
				return kvstore.Client().Status()
			},
			OnStatusUpdate: func(status status.Status) {
				state := models.StatusStateOk
				msg := ""

				if status.Err != nil {
					state = models.StatusStateFailure
					msg += fmt.Sprintf("Err: %s", status.Err)
				}
				// TODO(brb) do we really need this Err %s - %s?
				if info, ok := status.Data.(string); ok {
					format := " %s"
					if status.Err != nil {
						format = " - %s"
					}
					msg += fmt.Sprintf(format, info)
				}

				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				d.statusResponse.Kvstore = &models.Status{
					State: state,
					Msg:   msg,
				}
			},
		},
		{
			Name: "container-runtime",
			Probe: func(ctx context.Context) (interface{}, error) {
				return workloads.Status(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err != nil {
					d.statusResponse.ContainerRuntime = &models.Status{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}

				if s, ok := status.Data.(*models.Status); ok {
					d.statusResponse.ContainerRuntime = s
				}
			},
		},
		{
			Name: "kubernetes",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.getK8sStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err != nil {
					d.statusResponse.Kubernetes = &models.K8sStatus{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.K8sStatus); ok {
					d.statusResponse.Kubernetes = s
				}
			},
		},
		{
			Name: "ipam",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.DumpIPAM(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// IPAMStatus has no way to show errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.IPAMStatus); ok {
						d.statusResponse.IPAM = s
					}
				}
			},
		},
		{
			Name: "node-monitor",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.nodeMonitor.State(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// NodeMonitor has no way to show errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.MonitorStatus); ok {
						d.statusResponse.NodeMonitor = s
					}
				}
			},
		},
		{
			Name: "cluster",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.getNodeStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ClusterStatus has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.ClusterStatus); ok {
						if d.statusResponse.Cluster != nil {
							// NB: CiliumHealth is set concurrently by the
							// "cilium-health" probe, so do not override it
							s.CiliumHealth = d.statusResponse.Cluster.CiliumHealth
						}
						d.statusResponse.Cluster = s
					}
				}
			},
		},
		{
			Name: "cilium-health",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.ciliumHealth == nil {
					return nil, nil
				}
				return d.ciliumHealth.GetStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				if d.ciliumHealth == nil {
					return
				}

				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if d.statusResponse.Cluster == nil {
					d.statusResponse.Cluster = &models.ClusterStatus{}
				}
				if status.Err != nil {
					d.statusResponse.Cluster.CiliumHealth = &models.Status{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.Status); ok {
					d.statusResponse.Cluster.CiliumHealth = s
				}
			},
		},
		{
			Name: "l7-proxy",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.l7Proxy == nil {
					return nil, nil
				}
				return d.l7Proxy.GetStatusModel(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ProxyStatus has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.ProxyStatus); ok {
						d.statusResponse.Proxy = s
					}
				}
			},
		},
		{
			Name: "controllers",
			Probe: func(ctx context.Context) (interface{}, error) {
				return controller.GetGlobalStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ControllerStatuses has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(models.ControllerStatuses); ok {
						d.statusResponse.Controllers = s
					}
				}
			},
		},
	}

	d.statusCollector = status.NewCollector(probes, status.Config{
		Interval:         5 * time.Second,
		WarningThreshold: 15 * time.Second,
		FailureThreshold: time.Minute,
	})

	return
}
