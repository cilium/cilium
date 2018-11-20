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
	"net/url"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/containerd/containerd"
	apiEvents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl"
	"github.com/sirupsen/logrus"
)

const (
	ContainerD workloadRuntimeType = "containerd"

	// criContainerdPrefix is common prefix for cri-containerd
	criContainerdPrefix = "io.cri-containerd"
	// containerKindLabel is a label key indicating container is sandbox container or application container
	containerKindLabel = criContainerdPrefix + ".kind"
	// containerKindSandbox is a label value indicating container is sandbox container
	containerKindSandbox = "sandbox"

	// containerDEndpoint is the default value for the containerd socket
	containerDEndpoint = "/var/run/containerd/containerd.sock"

	// k8sContainerdNamespace is the namespace kubernetes uses to connect containerd.
	k8sContainerdNamespace = "k8s.io"
)

var (
	containerDInstance = &containerDModule{
		opts: workloadRuntimeOpts{
			epOpt: &workloadRuntimeOpt{
				description: "Address of containerD endpoint",
				value:       containerDEndpoint,
			},
		},
	}
)

type containerDModule struct {
	opts workloadRuntimeOpts
}

func init() {
	registerWorkload(ContainerD, containerDInstance)
}

func (c *containerDModule) getName() string {
	return string(ContainerD)
}

func (c *containerDModule) setConfigDummy() {
}

func (c *containerDModule) setConfig(opts map[string]string) error {
	return setOpts(opts, c.opts)
}

func (c *containerDModule) getConfig() map[string]string {
	return getOpts(c.opts)
}

func (c *containerDModule) newClient() (WorkloadRuntime, error) {
	return newContainerDClient(c.opts)
}

type containerDClient struct {
	*containerd.Client
	cri *criClient
}

func newContainerDClient(opts workloadRuntimeOpts) (WorkloadRuntime, error) {
	ep := string(opts[epOpt].value)
	c, err := containerd.New(ep)
	if err != nil {
		return nil, err
	}
	p, err := url.Parse(ep)
	if err != nil {
		return nil, err
	}
	if p.Scheme == "" {
		ep = "unix://" + ep
	}
	rsc, err := newCRIClient(context.WithValue(context.Background(), epOpt, ep))
	return &containerDClient{c, rsc}, err
}

// IsRunning returns false if the provided endpoint cannot be associated with a
// running workload. The runtime must be reachable to make this decision.
func (c *containerDClient) IsRunning(ep *endpoint.Endpoint) bool {
	return c.cri.IsRunning(ep)
}

// Status returns the status of the workload runtime
func (c *containerDClient) Status() *models.Status {
	if c == nil {
		return &models.Status{State: models.StatusStateDisabled}
	}

	criStatus := c.cri.Status()
	criStatusMsg := fmt.Sprintf("cri-containerd client: %s - %s", criStatus.State, criStatus.Msg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Client.Version(ctx); err != nil {
		return &models.Status{
			State: models.StatusStateFailure,
			Msg: fmt.Sprintf(
				"containerD events watcher: %s - %s; "+criStatusMsg,
				models.StatusStateFailure, err),
		}
	}

	return &models.Status{
		State: models.StatusStateOk,
		Msg:   fmt.Sprintf("containerD events watcher: %s; "+criStatusMsg, models.StatusStateOk),
	}
}

const (
	syncRateContainerD = 30 * time.Second
)

// EnableEventListener watches for containerD events. Performs the plumbing for
// the containers started or dead.
func (c *containerDClient) EnableEventListener() (eventsCh chan<- *EventMessage, err error) {
	if c == nil {
		log.Debug("Not enabling containerD event listener because containerDClient is nil")
		return nil, nil
	}
	log.Info("Enabling containerD event listener")

	ws := newWatcherState(eventQueueBufferSize)
	// start a go routine which periodically synchronizes containers
	// managed by the local container runtime and checks if any of them
	// need to be managed by Cilium. This is a fall back mechanism in case
	// an event notification has been lost.
	// Note: We do the sync before the first sleep
	go func(state *watcherState) {
		for {
			state.reapEmpty()
			ws.syncWithRuntime()
			time.Sleep(syncRateContainerD)
		}
	}(ws)

	// Note: We do the sync before the first sleep
	go func(state *watcherState) {
		for {
			eventsCh, errCh := c.Client.Subscribe(context.Background(), `topic~="/containers/create"`, `topic~="/containers/delete"`)
			err := c.listenForContainerDEvents(ws, eventsCh, errCh)
			log.WithError(err).Errorf("failed to listen events")
		}
	}(ws)
	return nil, nil
}

func (c *containerDClient) listenForContainerDEvents(ws *watcherState, eventsCh <-chan *events.Envelope, errCh <-chan error) error {
	open := true
	for open {
		var e *events.Envelope
		select {
		case e, open = <-eventsCh:
		case err := <-errCh:
			return fmt.Errorf("unable to subscribe for containerd events: %s", err)
		}

		if e.Event != nil {
			v, err := typeurl.UnmarshalAny(e.Event)
			if err != nil {
				return fmt.Errorf("unable to unmarshal event %v: %s", v, err)
			}
			switch event := v.(type) {
			case *apiEvents.ContainerCreate:
				ws.enqueueByContainerID(event.ID, &EventMessage{WorkloadID: event.ID, EventType: EventTypeStart})
			case *apiEvents.ContainerDelete:
				ws.enqueueByContainerID(event.ID, &EventMessage{WorkloadID: event.ID, EventType: EventTypeDelete})
			default:
				log.Debugf("received unknown containerD event %v", v)
			}
		}
	}

	return fmt.Errorf("channel closed")
}

func (c *containerDClient) processEvents(events chan EventMessage) {
	for m := range events {
		if m.WorkloadID != "" {
			log.WithFields(logrus.Fields{
				logfields.ContainerID: shortContainerID(m.WorkloadID),
			}).Debug("Processing event for Container")
			c.processEvent(m)
		}
	}
}

func (c *containerDClient) processEvent(m EventMessage) {
	switch m.EventType {
	case EventTypeStart:
		ns := namespaces.WithNamespace(context.Background(), k8sContainerdNamespace)
		f, err := c.Client.ContainerService().Get(ns, m.WorkloadID)
		if err != nil {
			log.WithError(err).Debugf("Unable to get more details for workload %s", m.WorkloadID)
			return
		}
		// only handle pod events and ignore all other types
		if f.Labels[containerKindLabel] != containerKindSandbox {
			startIgnoringContainer(m.WorkloadID)
			return
		}
		stopIgnoringContainer(m.WorkloadID)
		c.handleCreateWorkload(m.WorkloadID, true)
	case EventTypeDelete:
		Owner().DeleteEndpoint(endpointid.NewID(endpointid.ContainerIdPrefix, m.WorkloadID))
	}
}

func (c *containerDClient) handleCreateWorkload(id string, retry bool) {
	c.cri.handleCreateWorkload(id, retry)
}

// IgnoreRunningWorkloads checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func (c *containerDClient) IgnoreRunningWorkloads() {
	c.cri.IgnoreRunningWorkloads()
}

// workloadIDsList returns a list of running workload IDs.
func (c *containerDClient) workloadIDsList(ctx context.Context) ([]string, error) {
	return c.cri.workloadIDsList(ctx)
}

// GetAllInfraContainersPID returns a map that maps container IDs to the PID
// of that container.
func (c *containerDClient) GetAllInfraContainersPID() (map[string]int, error) {
	return nil, errors.New("not implemented")
}
