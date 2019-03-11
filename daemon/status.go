// Copyright 2016-2019 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	versionapi "k8s.io/apimachinery/pkg/version"
)

const (
	// k8sVersionCheckInterval is the interval in which the Kubernetes
	// version is verified even if connectivity is given
	k8sVersionCheckInterval = 5 * time.Minute

	// k8sMinimumEventHearbeat is the time interval in which any received
	// event will be considered proof that the apiserver connectivity is
	// healthty
	k8sMinimumEventHearbeat = time.Minute
)

type k8sVersion struct {
	version          string
	lastVersionCheck time.Time
	lock             lock.Mutex
}

func (k *k8sVersion) cachedVersion() (string, bool) {
	k.lock.Lock()
	defer k.lock.Unlock()

	if time.Since(k8smetrics.LastInteraction.Time()) > k8sMinimumEventHearbeat {
		return "", false
	}

	if k.version == "" || time.Since(k.lastVersionCheck) > k8sVersionCheckInterval {
		return "", false
	}

	return k.version, true
}

func (k *k8sVersion) update(version *versionapi.Info) string {
	k.lock.Lock()
	defer k.lock.Unlock()

	k.version = fmt.Sprintf("%s.%s (%s) [%s]", version.Major, version.Minor, version.GitVersion, version.Platform)
	k.lastVersionCheck = time.Now()
	return k.version
}

var k8sVersionCache k8sVersion

func (d *Daemon) getK8sStatus() *models.K8sStatus {
	if !k8s.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}
	}

	version, valid := k8sVersionCache.cachedVersion()
	if !valid {
		k8sVersion, err := k8s.Client().Discovery().ServerVersion()
		if err != nil {
			return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
		}

		version = k8sVersionCache.update(k8sVersion)
	}

	k8sStatus := &models.K8sStatus{
		State:          models.StatusStateOk,
		Msg:            version,
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
	clusterStatus := models.ClusterStatus{
		Self: d.nodeDiscovery.LocalNode.Fullname(),
	}
	for _, node := range d.nodeDiscovery.Manager.GetNodes() {
		clusterStatus.Nodes = append(clusterStatus.Nodes, node.GetModel())
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

	// d.statusResponse contains references, so we do a deep copy to be able to
	// safely use sr after the method has returned
	sr := *d.statusResponse.DeepCopy()

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
				var msg string
				state := models.StatusStateOk
				info, ok := status.Data.(string)

				switch {
				case ok && status.Err != nil:
					state = models.StatusStateFailure
					msg = fmt.Sprintf("Err: %s - %s", status.Err, info)
				case status.Err != nil:
					state = models.StatusStateFailure
					msg = fmt.Sprintf("Err: %s", status.Err)
				case ok:
					msg = fmt.Sprintf("%s", info)
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
			Interval: func(failures int) time.Duration {
				if failures > 0 {
					// While failing, we want an initial
					// quick retry with exponential backoff
					// to avoid continous load on the
					// apiserver
					return backoff.CalculateDuration(5*time.Second, 2*time.Minute, 2.0, false, failures)
				}

				// The base interval is dependant on the
				// cluster size. One status interval does not
				// automatically translate to an apiserver
				// interaction as any regular apiserver
				// interaction is also used as an indication of
				// successfull connectivity so we can continue
				// to be fairly aggressive.
				//
				// 1     |    7s
				// 2     |   12s
				// 4     |   15s
				// 64    |   42s
				// 512   | 1m02s
				// 2048  | 1m15s
				// 8192  | 1m30s
				// 16384 | 1m32s
				return d.nodeDiscovery.Manager.ClusterSizeDependantInterval(10 * time.Second)
			},
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

	d.statusCollector = status.NewCollector(probes, status.Config{})

	return
}
