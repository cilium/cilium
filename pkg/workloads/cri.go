// Copyright 2018 Authors of Cilium
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
//
package workloads

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/containerd/containerd/namespaces"
	criStore "github.com/containerd/cri/pkg/store"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	criRuntime "k8s.io/kubernetes/pkg/kubelet/apis/cri/runtime/v1alpha2"
	"k8s.io/kubernetes/pkg/kubelet/util"
)

func getGRPCCLient(ctx context.Context) (*grpc.ClientConn, error) {
	ep, ok := ctx.Value(EpOpt).(string)
	if !ok {
		return nil, fmt.Errorf("unknown runtime endpoint")
	}
	log.Debugf("using CRI endpoint %s", ep)
	addr, dialer, err := util.GetAddressAndDialer(ep)
	if err != nil {
		return nil, err
	}

	c, cancel := context.WithTimeout(ctx, time.Duration(5*time.Second))
	defer cancel()

	conn, err := grpc.DialContext(c, addr, grpc.WithDialer(dialer), grpc.WithInsecure(), grpc.WithBackoffMaxDelay(15*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %s", err)
	}
	return conn, nil
}

type criClient struct {
	criRuntime.RuntimeServiceClient
}

func newCRIClient(ctx context.Context) (*criClient, error) {
	cc, err := getGRPCCLient(ctx)
	if err != nil {
		return nil, err
	}
	rsc := criRuntime.NewRuntimeServiceClient(cc)
	return &criClient{rsc}, nil
}

// IsRunning returns false if the provided endpoint cannot be associated with a
// running workload. The runtime must be reachable to make this decision.
func (c *criClient) IsRunning(ep *endpoint.Endpoint) bool {
	if c == nil {
		return false
	}

	podID := ep.GetContainerID()

	if podID == "" {
		return false
	}

	pssr := criRuntime.PodSandboxStatusRequest{
		PodSandboxId: podID,
	}
	ns := namespaces.WithNamespace(context.Background(), k8sContainerdNamespace)
	cont, err := c.RuntimeServiceClient.PodSandboxStatus(ns, &pssr)
	if err == criStore.ErrNotExist {
		return false
	}
	if err != nil {
		log.WithError(err).Debugf("unable to get pod sandbox status of %v", pssr)
		return false
	}

	return cont.GetStatus().State == criRuntime.PodSandboxState_SANDBOX_READY
}

// Status returns the status of the workload runtime
func (c *criClient) Status() *models.Status {
	if c == nil {
		return &models.Status{State: models.StatusStateDisabled}
	}

	sreq := &criRuntime.StatusRequest{
		Verbose: false,
	}
	sresp, err := c.RuntimeServiceClient.Status(context.Background(), sreq)
	if err != nil {
		return &models.Status{State: models.StatusStateFailure, Msg: err.Error()}
	}
	for _, runtimeCondition := range sresp.Status.Conditions {
		if !runtimeCondition.Status {
			return &models.Status{State: models.StatusStateFailure, Msg: runtimeCondition.Message}
		}

	}
	return &models.Status{State: models.StatusStateOk, Msg: "cri daemon: Ok"}
}

// EnableEventListener watches for containerD events. Performs the plumbing for the
// containers started or dead.
func (c *criClient) EnableEventListener() (chan<- *EventMessage, error) {
	if c == nil {
		log.Debug("Not enabling CRI event listener because CRI client is nil")
		return nil, nil
	}
	log.Info("Enabling CRI event listener")

	ws := newWatcherState()

	eventsCh := make(chan *EventMessage, 100)
	go func(state *watcherState, eventsCh <-chan *EventMessage) {
		for event := range eventsCh {
			ws.enqueueByContainerID(event.WorkloadID, event)
		}
	}(ws, eventsCh)
	return eventsCh, nil
}

func (c *criClient) processEvent(m EventMessage) {
	switch m.EventType {
	case EventTypeStart:
		req := &criRuntime.PodSandboxStatusRequest{
			PodSandboxId: m.WorkloadID,
		}
		_, err := c.PodSandboxStatus(context.Background(), req)
		if err != nil {
			// ignore containers if not found
			//	startIgnoringContainer(m.WorkloadID)
			log.WithError(err).Debugf("Unable to get more details for workload %s", m.WorkloadID)
			return
		}
		stopIgnoringContainer(m.WorkloadID)
		c.handleCreateWorkload(m.WorkloadID, true)
	case EventTypeDelete:
		Owner().DeleteEndpoint(endpointid.NewID(endpointid.ContainerIdPrefix, m.WorkloadID))
	}
}

func (c *criClient) processEvents(events chan EventMessage) {
	for m := range events {
		if m.WorkloadID != "" {
			log.WithFields(logrus.Fields{
				logfields.ContainerID: shortContainerID(m.WorkloadID),
			}).Debug("Processing event for Container")
			c.processEvent(m)
		}
	}
}

func (c *criClient) getEndpointByPodIP(pod *criRuntime.PodSandboxStatus) *endpoint.Endpoint {
	scopedLog := log.WithField(logfields.ContainerID, shortContainerID(pod.GetId()))

	if ciliumIP := c.getCiliumIP(pod); ciliumIP != nil {
		id := endpointid.NewIPPrefixID(ciliumIP.IP())
		if ep, err := endpointmanager.Lookup(id); err != nil {
			log.WithError(err).Warning("Unable to lookup endpoint by IP prefix")
		} else if ep != nil {
			return ep
		}
	}

	scopedLog.Debug("IP address assigned by Cilium could not be derived from pod")
	return nil
}

func (c *criClient) getCiliumIP(pod *criRuntime.PodSandboxStatus) addressing.CiliumIP {
	ip := net.ParseIP(pod.GetNetwork().GetIp())
	if ip == nil {
		return nil
	}
	if ip.To4() == nil {
		return addressing.DeriveCiliumIPv4(ip)
	}
	return addressing.DeriveCiliumIPv6(ip)
}

func (c *criClient) handleCreateWorkload(id string, retry bool) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ContainerID: shortContainerID(id),
		fieldMaxRetry:         EndpointCorrelationMaxRetries,
		"willRetry":           retry,
	})

	for try := 1; try <= EndpointCorrelationMaxRetries; try++ {
		retryLog := scopedLog.WithFields(logrus.Fields{
			"retry": try,
			"podID": id,
		})

		if try > 1 {
			if retry {
				retryLog.Debug("Waiting for endpoint representing pod to appear")
				time.Sleep(EndpointCorrelationSleepTime(try))
			} else {
				break
			}
		}

		ctx := namespaces.WithNamespace(context.Background(), k8sContainerdNamespace)
		pssr := criRuntime.PodSandboxStatusRequest{
			PodSandboxId: id,
		}
		cont, err := c.RuntimeServiceClient.PodSandboxStatus(ctx, &pssr)
		if err != nil {
			retryLog.WithError(err).Debugf("Unable to inspect pod %s after pod create event", id)
			continue
		}

		pod := cont.GetStatus()
		if pod.GetId() == "" {
			retryLog.Warn("Container name not set in event from containerD")
		}

		ep := endpointmanager.LookupContainerID(id)
		if ep == nil {
			// Container ID is not yet known; try and find endpoint
			// via one of the IP addresses assigned.
			ep = c.getEndpointByPodIP(pod)
		}

		if ep == nil {
			// Endpoint does not exist yet. This indicates that the
			// orchestration system has not requested us to handle
			// networking for this pod yet (or never will).
			// We will retry a couple of times to wait for this to
			// happen.
			retryLog.Debug("Container event could not be associated with endpoint yet")
			continue
		}

		retryLog.WithFields(logrus.Fields{
			logfields.EndpointID: ep.ID,
		}).Debug("Associated container event with endpoint")

		processCreateWorkload(ep, id, pod.Labels)
		return
	}

	startIgnoringContainer(id)

	scopedLog.Info("No request received to manage networking for container")
}

// IgnoreRunningWorkloads checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func (c *criClient) IgnoreRunningWorkloads() {
	if c == nil {
		return
	}

	req := &criRuntime.ListPodSandboxRequest{}

	resp, err := c.RuntimeServiceClient.ListPodSandbox(context.Background(), req)
	if err != nil {
		log.WithError(err).Error("unable to get list of pods running")
		return
	}
	for _, pod := range resp.GetItems() {
		scopedLog := log.WithField(logfields.ContainerID, pod.GetId())
		scopedLog.Info("Adding running container to the list of ignored containers")
		startIgnoringContainer(pod.GetId())
		ctx := namespaces.WithNamespace(context.Background(), k8sContainerdNamespace)
		pssr := criRuntime.PodSandboxStatusRequest{
			PodSandboxId: pod.GetId(),
		}
		cont, err := c.RuntimeServiceClient.PodSandboxStatus(ctx, &pssr)
		if err != nil {
			continue
		}
		cIP := c.getCiliumIP(cont.GetStatus())
		if cIP == nil {
			continue
		}
		allocator.Blacklist(cIP.IP(), "ignored container: "+pod.GetId())
		//TODO Release this address when the ignored container leaves
		scopedLog.WithFields(logrus.Fields{
			logfields.IPAddr: cIP.IP(),
		}).Info("Found container running with potential " +
			"collision IP address, adding to the list " +
			"of allocated IPs")
	}
}

// workloadIDsList returns a list of running workload IDs.
func (c *criClient) workloadIDsList(ctx context.Context) ([]string, error) {
	ctx = namespaces.WithNamespace(ctx, k8sContainerdNamespace)
	req := &criRuntime.ListPodSandboxRequest{}
	resp, err := c.RuntimeServiceClient.ListPodSandbox(ctx, req)
	if err != nil {
		return nil, err
	}

	cont := []string{}
	for _, pod := range resp.GetItems() {
		if pod.GetId() != "" {
			cont = append(cont, pod.GetId())
		}
	}
	return cont, nil
}

// GetAllInfraContainersPID returns a map that maps container IDs to the PID
// of that container.
func (c *criClient) GetAllInfraContainersPID() (map[string]int, error) {
	return nil, errors.New("not implemented")
}
