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
	"math/rand"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/k8s"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
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
	k8sVersionCheckInterval = 15 * time.Minute

	// k8sMinimumEventHearbeat is the time interval in which any received
	// event will be considered proof that the apiserver connectivity is
	// healthty
	k8sMinimumEventHearbeat = time.Minute
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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
	brief := params.Brief != nil && *params.Brief
	sr := h.daemon.getStatus(brief)

	return NewGetHealthzOK().WithPayload(&sr)
}

type getNodes struct {
	d *Daemon
	// mutex to protect the clients map against concurrent access
	lock.RWMutex
	// clients maps a client ID to a clusterNodesClient
	clients map[int64]*clusterNodesClient
}

func NewGetClusterNodesHandler(d *Daemon) GetClusterNodesHandler {
	return &getNodes{
		d:       d,
		clients: map[int64]*clusterNodesClient{},
	}
}

// clientGCTimeout is the time for which the clients are kept. After timeout
// is reached, clients will be cleaned up.
const clientGCTimeout = 15 * time.Minute

type clusterNodesClient struct {
	// mutex to protect the client against concurrent access
	lock.RWMutex
	lastSync time.Time
	*models.ClusterNodeStatus
}

func (c *clusterNodesClient) NodeAdd(newNode node.Node) error {
	c.Lock()
	c.NodesAdded = append(c.NodesAdded, newNode.GetModel())
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) NodeUpdate(oldNode, newNode node.Node) error {
	c.Lock()
	c.NodesAdded = append(c.NodesAdded, newNode.GetModel())
	c.NodesRemoved = append(c.NodesRemoved, oldNode.GetModel())
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) NodeDelete(node node.Node) error {
	c.Lock()
	// If the node was added/updated and removed before the clusterNodesClient
	// was aware of it then we can safely remove it from the list of added
	// nodes and not set it in the list of removed nodes.
	found := -1
	for i, added := range c.NodesAdded {
		if added.Name == node.Fullname() {
			found = i
		}
	}
	if found != -1 {
		c.NodesAdded = append(c.NodesAdded[:found], c.NodesAdded[found+1:]...)
	} else {
		c.NodesRemoved = append(c.NodesRemoved, node.GetModel())
	}
	c.Unlock()
	return nil
}

func (c *clusterNodesClient) NodeValidateImplementation(node node.Node) error {
	// no-op
	return nil
}

func (c *clusterNodesClient) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	// no-op
	return nil
}

func (h *getNodes) cleanupClients() {
	past := time.Now().Add(-clientGCTimeout)
	for k, v := range h.clients {
		if v.lastSync.Before(past) {
			h.d.nodeDiscovery.Manager.Unsubscribe(v)
			delete(h.clients, k)
		}
	}
}

func (h *getNodes) Handle(params GetClusterNodesParams) middleware.Responder {
	var cns *models.ClusterNodeStatus
	// If ClientID is not set then we send all nodes, otherwise we will store
	// the client ID in the list of clients and we subscribe this new client
	// to the list of clients.
	if params.ClientID == nil {
		ns := h.d.getNodeStatus()
		cns = &models.ClusterNodeStatus{
			Self:       ns.Self,
			NodesAdded: ns.Nodes,
		}
		return NewGetClusterNodesOK().WithPayload(cns)
	}

	h.Lock()
	defer h.Unlock()

	var clientID int64
	c, exists := h.clients[*params.ClientID]
	if exists {
		clientID = *params.ClientID
	} else {
		clientID = rand.Int63()
		// make sure we haven't allocated an existing client ID nor the
		// randomizer has allocated ID 0, if we have then we will return
		// clientID 0.
		_, exists := h.clients[clientID]
		if exists || clientID == 0 {
			ns := h.d.getNodeStatus()
			cns = &models.ClusterNodeStatus{
				ClientID:   0,
				Self:       ns.Self,
				NodesAdded: ns.Nodes,
			}
			return NewGetClusterNodesOK().WithPayload(cns)
		}
		c = &clusterNodesClient{
			lastSync: time.Now(),
			ClusterNodeStatus: &models.ClusterNodeStatus{
				ClientID: clientID,
				Self:     h.d.nodeDiscovery.LocalNode.Fullname(),
			},
		}
		h.d.nodeDiscovery.Manager.Subscribe(c)

		// Clean up other clients before adding a new one
		h.cleanupClients()
		h.clients[clientID] = c
	}
	c.Lock()
	// Copy the ClusterNodeStatus to the response
	cns = c.ClusterNodeStatus
	// Store a new ClusterNodeStatus to reset the list of nodes
	// added / removed.
	c.ClusterNodeStatus = &models.ClusterNodeStatus{
		ClientID: clientID,
		Self:     h.d.nodeDiscovery.LocalNode.Fullname(),
	}
	c.lastSync = time.Now()
	c.Unlock()

	return NewGetClusterNodesOK().WithPayload(cns)
}

// getStatus returns the daemon status. If brief is provided a minimal version
// of the StatusResponse is provided.
func (d *Daemon) getStatus(brief bool) models.StatusResponse {
	staleProbes := d.statusCollector.GetStaleProbes()
	stale := make(map[string]strfmt.DateTime, len(staleProbes))
	for probe, startTime := range staleProbes {
		stale[probe] = strfmt.DateTime(startTime)
	}

	d.statusCollectMutex.RLock()
	defer d.statusCollectMutex.RUnlock()

	var sr models.StatusResponse
	if brief {
		csCopy := new(models.ClusterStatus)
		if d.statusResponse.Cluster != nil && d.statusResponse.Cluster.CiliumHealth != nil {
			in, out := &d.statusResponse.Cluster.CiliumHealth, &csCopy.CiliumHealth
			*out = new(models.Status)
			**out = **in
		}
		var minimalControllers models.ControllerStatuses
		if d.statusResponse.Controllers != nil {
			for _, c := range d.statusResponse.Controllers {
				if c.Status == nil {
					continue
				}
				// With brief, the client should only care if a single controller
				// is failing and its status so we don't need to continuing
				// checking for failure messages for the remaining controllers.
				if c.Status.LastFailureMsg != "" {
					minimalControllers = append(minimalControllers, c.DeepCopy())
					break
				}
			}
		}
		sr = models.StatusResponse{
			Cluster:     csCopy,
			Controllers: minimalControllers,
		}
	} else {
		// d.statusResponse contains references, so we do a deep copy to be able to
		// safely use sr after the method has returned
		sr = *d.statusResponse.DeepCopy()
	}

	sr.Stale = stale

	switch {
	case len(sr.Stale) > 0:
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   "Stale status data",
		}
	case d.statusResponse.Kvstore != nil && d.statusResponse.Kvstore.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kvstore.State,
			Msg:   "Kvstore service is not ready",
		}
	case d.statusResponse.ContainerRuntime != nil && d.statusResponse.ContainerRuntime.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: d.statusResponse.ContainerRuntime.State,
			Msg:   "Container runtime is not ready",
		}
	case k8s.IsEnabled() && d.statusResponse.Kubernetes != nil && d.statusResponse.Kubernetes.State != models.StatusStateOk:
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kubernetes.State,
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
				if option.Config.KVStore == "" {
					return models.StatusStateDisabled, nil
				} else {
					return kvstore.Client().Status()
				}
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
					// to avoid continuous load on the
					// apiserver
					return backoff.CalculateDuration(5*time.Second, 2*time.Minute, 2.0, false, failures)
				}

				// The base interval is dependant on the
				// cluster size. One status interval does not
				// automatically translate to an apiserver
				// interaction as any regular apiserver
				// interaction is also used as an indication of
				// successful connectivity so we can continue
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
				return d.monitorAgent.State(), nil
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
				clusterStatus := &models.ClusterStatus{
					Self: d.nodeDiscovery.LocalNode.Fullname(),
				}
				return clusterStatus, nil
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
