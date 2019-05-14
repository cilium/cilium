// Copyright 2017-2018 Authors of Cilium
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

package workloads

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/connector"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/plugins/cilium-docker/driver"

	"github.com/containernetworking/plugins/pkg/ns"
	dTypes "github.com/docker/docker/api/types"
	dTypesEvents "github.com/docker/docker/api/types/events"
	dNetwork "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	ctx "golang.org/x/net/context"
	"golang.org/x/sys/unix"
)

const (
	Docker WorkloadRuntimeType = "docker"
)

var (
	dockerInstance = &dockerModule{
		opts: workloadRuntimeOpts{
			EpOpt: &workloadRuntimeOpt{
				description: "Addresses of docker endpoint",
				value:       "unix:///var/run/docker.sock",
			},
			DatapathModeOpt: &workloadRuntimeOpt{
				description: "Cilium datapath mode",
				value:       option.DatapathModeVeth,
			},
		},
	}
)

type dockerModule struct {
	opts workloadRuntimeOpts
}

func init() {
	registerWorkload(Docker, dockerInstance)
}

func (c *dockerModule) getName() string {
	return string(Docker)
}

func (c *dockerModule) setConfigDummy() {
}

func (c *dockerModule) setConfig(opts map[string]string) error {
	return setOpts(opts, c.opts)
}

func (c *dockerModule) getConfig() map[string]string {
	return getOpts(c.opts)
}

func (c *dockerModule) newClient() (WorkloadRuntime, error) {
	return newDockerClient(c.opts)
}

type dockerClient struct {
	*client.Client
	datapathMode string
}

func newDockerClient(opts workloadRuntimeOpts) (WorkloadRuntime, error) {
	defaultHeaders := map[string]string{"User-Agent": "cilium"}
	ep := opts[EpOpt]
	c, err := client.NewClient(ep.value, "v1.21", nil, defaultHeaders)
	if err != nil {
		return nil, err
	}
	dpMode, found := opts[DatapathModeOpt]
	if !found {
		return nil, fmt.Errorf("'%s' option not found", DatapathModeOpt)
	}

	return &dockerClient{Client: c, datapathMode: dpMode.value}, nil
}

func newDockerClientMock(opts workloadRuntimeOpts) (WorkloadRuntime, error) {
	mwc := newMockClient(networksMock())
	c, err := client.NewClient("http://127.0.0.1:2375", "v1.21", mwc, nil)
	if err != nil {
		return nil, err
	}

	return &dockerClient{Client: c}, nil
}

// Helper function to mock docker calls
type transportFunc func(*http.Request) (*http.Response, error)

// Helper function to mock docker calls
func (tf transportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return tf(req)
}

// Helper function to mock docker calls
func newMockClient(doer func(*http.Request) (*http.Response, error)) *http.Client {
	v := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	v.RegisterProtocol("http", transportFunc(doer))
	return &http.Client{
		Transport: http.RoundTripper(v),
	}
}

// Helper function to mock docker calls to networks endpoint
func networksMock() func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.Path, "/v1.21/networks") {
			return nil, fmt.Errorf("Only expecting /v1.21/networks requests, got %s", req.URL.Path)
		}

		header := http.Header{}
		header.Set("Content-Type", "application/json")

		body, err := json.Marshal(&dTypes.NetworkResource{
			Name:       "12345",
			ID:         "1234",
			Scope:      "global",
			Driver:     "cilium-net",
			EnableIPv6: true,
			IPAM:       dNetwork.IPAM{},
			Internal:   false,
			// this map contains all endpoints except 259
			Containers: map[string]dTypes.EndpointResource{
				"603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def00100256": {
					EndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d800200256",
				},
				"603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def00100257": {
					EndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d800200257",
				},
				"603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def00100258": {
					EndpointID: "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d800100258",
				},
			},
			Options: map[string]string{},
			Labels:  map[string]string{},
		})
		if err != nil {
			return nil, err
		}

		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewReader(body)),
			Header:     header,
		}, nil
	}
}

// IsRunning returns false if the provided endpoint cannot be associated with a
// running workload. The runtime must be reachable to make this decision.
func (d *dockerClient) IsRunning(ep *endpoint.Endpoint) bool {
	if d == nil {
		return false
	}

	runtimeRunning := false

	networkID := ep.GetDockerNetworkID()
	containerID := ep.GetContainerID()

	if networkID != "" {
		nls, err := d.NetworkInspect(ctx.Background(), networkID, dTypes.NetworkInspectOptions{})
		if client.IsErrNotFound(err) {
			return false
		}

		if err == nil {
			runtimeRunning = true
			found := false
			for _, v := range nls.Containers {
				if v.EndpointID == ep.DockerEndpointID {
					found = true
					break
				}
			}

			if found {
				return found
			}
		}
	}

	if containerID != "" {
		cont, err := d.ContainerInspect(ctx.Background(), containerID)
		if client.IsErrNotFound(err) {
			return false
		}

		if err == nil {
			runtimeRunning = true

			// Container may exist but is not in running state
			return cont.State.Running
		}
	}

	return !runtimeRunning
}

// Status returns the status of the workload runtime
func (d *dockerClient) Status() *models.Status {
	if d == nil {
		return &models.Status{State: models.StatusStateDisabled}
	}

	if _, err := d.Info(ctx.Background()); err != nil {
		return &models.Status{State: models.StatusStateFailure, Msg: "docker daemon: " + err.Error()}
	}

	return &models.Status{State: models.StatusStateOk, Msg: "docker daemon: OK"}
}

// EnableEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func (d *dockerClient) EnableEventListener() (chan<- *EventMessage, error) {
	if d == nil {
		log.Debug("Not enabling docker event listener because dockerClient is nil")
		return nil, nil
	}
	log.Info("Enabling docker event listener")

	ws := newWatcherState()

	since := time.Now()
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(since.Unix(), 10)}
	r, err := d.Events(ctx.Background(), eo)

	go d.listenForDockerEvents(ws, r, err)

	log.Debug("Started to listen for docker events")
	return nil, nil
}

func (d *dockerClient) listenForDockerEvents(ws *watcherState, messagesCh <-chan dTypesEvents.Message, errCh <-chan error) {
	for {
		select {
		case err, ok := <-errCh:
			if !ok || err == io.EOF {
				log.Info("Docker error channel closed")
				return
			}
			log.WithError(err).Error("Error while reading docker events")
			// Sleep to avoid consuming 100% CPU
			time.Sleep(100 * time.Millisecond)
		case e, ok := <-messagesCh:
			metrics.EventTSContainerd.SetToCurrentTime()
			if !ok {
				log.Error("docker events channel closed")
				return
			}
			if e.ID == "" || e.Type != "container" {
				continue
			}
			log.WithFields(logrus.Fields{
				"event":               e.Status,
				logfields.ContainerID: shortContainerID(e.ID),
			}).Debug("Queueing container event")

			switch e.Status {
			case "start":
				ws.enqueueByContainerID(e.ID, &EventMessage{WorkloadID: e.ID, EventType: EventTypeStart})
			case "die":
				ws.enqueueByContainerID(e.ID, &EventMessage{WorkloadID: e.ID, EventType: EventTypeDelete})
			}
		}
	}
}

func (d *dockerClient) processEvents(events chan EventMessage) {
	for m := range events {
		if m.WorkloadID != "" {
			log.WithFields(logrus.Fields{
				"event":               m.EventType,
				logfields.ContainerID: shortContainerID(m.WorkloadID),
			}).Debug("Processing event for Container")
			d.processEvent(m)
		}
	}
}

func (d *dockerClient) processEvent(m EventMessage) {
	switch m.EventType {
	case EventTypeStart:
		// A real event overwrites any memory of ignored containers
		stopIgnoringContainer(m.WorkloadID)
		d.handleCreateWorkload(m.WorkloadID, true)
	case EventTypeDelete:
		Owner().DeleteEndpoint(endpointid.NewID(endpointid.ContainerIdPrefix, m.WorkloadID))
	}
}

func (d *dockerClient) getEndpointByIP(cont *dTypes.ContainerJSON) *endpoint.Endpoint {
	scopedLog := log.WithField(logfields.ContainerID, shortContainerID(cont.ID))

	if cont.NetworkSettings == nil {
		scopedLog.Debug("No network settings included in event")
		return nil
	}

	for _, contNetwork := range cont.NetworkSettings.Networks {
		if contNetwork == nil {
			continue
		}

		if contNetwork.GlobalIPv6Address != "" {
			id := endpointid.NewID(endpointid.IPv6Prefix, contNetwork.GlobalIPv6Address)
			if ep, err := endpointmanager.Lookup(id); err != nil {
				log.WithError(err).WithField(logfields.V6Prefix, id).Warning("Unable to lookup endpoint by IP prefix")
			} else if ep != nil {
				return ep
			}
		}

		if contNetwork.IPAddress != "" {
			id := endpointid.NewID(endpointid.IPv4Prefix, contNetwork.IPAddress)
			if ep, err := endpointmanager.Lookup(id); err != nil {
				log.WithError(err).WithField(logfields.V4Prefix, id).Warning("Unable to lookup endpoint by IP prefix")
			} else if ep != nil {
				return ep
			}
		}
	}

	scopedLog.Debug("IP address assigned by Cilium could not be derived from pod")
	return nil
}

func (d *dockerClient) getCiliumIPv6(networks map[string]*dNetwork.EndpointSettings) *addressing.CiliumIPv6 {
	for _, contNetwork := range networks {
		if contNetwork == nil {
			continue
		}

		scopedLog := log.WithField(logfields.EndpointID, contNetwork.EndpointID)

		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if !ipv6gw.Equal(node.GetIPv6Router()) {
			scopedLog.WithField(logfields.Object, contNetwork).Debug("Skipping network because of gateway mismatch")
			continue
		}
		ip, err := addressing.NewCiliumIPv6(contNetwork.GlobalIPv6Address)
		if err == nil {
			return &ip
		}
	}
	return nil
}

func (d *dockerClient) handleCreateWorkload(id string, retry bool) {
	var sandboxKey string // path to the container network namespace

	scopedLog := log.WithFields(logrus.Fields{
		logfields.ContainerID: shortContainerID(id),
		fieldMaxRetry:         EndpointCorrelationMaxRetries,
		"willRetry":           retry,
	})

	for try := 1; try <= EndpointCorrelationMaxRetries; try++ {
		retryLog := scopedLog.WithField("retry", try)

		if try > 1 {
			if retry {
				retryLog.Debug("Waiting for endpoint representing container to appear")
				time.Sleep(EndpointCorrelationSleepTime(try))
			} else {
				break
			}
		}

		dockerContainer, err := d.ContainerInspect(ctx.Background(), id)
		if err != nil {
			retryLog.WithError(err).Debug("Unable to inspect container after container create event")
			continue
		}

		containerName := dockerContainer.Name
		if containerName == "" {
			retryLog.Warn("Container name not set in event from docker")
		}

		ep := endpointmanager.LookupContainerID(id)
		if ep == nil {
			// Container ID is not yet known; try and find endpoint via
			// the IP address assigned.
			ep = d.getEndpointByIP(&dockerContainer)
		}

		if ep == nil {
			// Endpoint does not exist yet. This indicates that the
			// orchestration system has not requested us to handle
			// networking for this container yet (or never will).
			// We will retry a couple of times to wait for this to
			// happen.
			retryLog.WithFields(logrus.Fields{
				"containerName": containerName,
			}).Debug("Container event could not be associated with endpoint yet")
			continue
		}

		retryLog.WithFields(logrus.Fields{
			"containerName":      containerName,
			logfields.EndpointID: ep.ID,
		}).Debug("Associated container event with endpoint")

		if dockerContainer.NetworkSettings != nil {
			sandboxKey = dockerContainer.NetworkSettings.SandboxKey
			id := dockerContainer.NetworkSettings.EndpointID
			if id != "" {
				ep.SetDockerEndpointID(id)
			}
		}

		// Docker appends '/' to container names.
		ep.SetContainerName(strings.Trim(containerName, "/"))

		// Finish ipvlan initialization if endpoint is connected via Docker libnetwork (cilium-docker)
		if ep.GetDockerNetworkID() != "" && d.datapathMode == option.DatapathModeIpvlan {
			if err := finishIpvlanInit(ep, sandboxKey); err != nil {
				retryLog.WithError(err).Warn("Cannot finish ipvlan initialization")
				continue
			}
		}

		allLabels := map[string]string{}
		if dockerContainer.Config != nil {
			allLabels = dockerContainer.Config.Labels
		}

		processCreateWorkload(ep, id, allLabels)

		return
	}

	startIgnoringContainer(id)

	scopedLog.Info("No request received to manage networking for container")
}

// IgnoreRunningWorkloads checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func (d *dockerClient) IgnoreRunningWorkloads() {
	if d == nil {
		return
	}

	conts, err := d.ContainerList(ctx.Background(), dTypes.ContainerListOptions{})
	if err != nil {
		return
	}
	for _, cont := range conts {
		scopedLog := log.WithField(logfields.ContainerID, cont.ID)
		scopedLog.Info("Adding running container to the list of ignored containers")
		startIgnoringContainer(cont.ID)
		if cont.NetworkSettings == nil {
			continue
		}
		cIP := d.getCiliumIPv6(cont.NetworkSettings.Networks)
		if cIP == nil {
			continue
		}
		allocator.Blacklist(cIP.IP(), "ignored docker container: "+cont.ID)
		// TODO Release this address when the ignored container leaves
		scopedLog.WithFields(logrus.Fields{
			logfields.IPAddr: cIP.IP(),
		}).Info("Found container running with potential " +
			"collision IP address, adding to the list " +
			"of allocated IPs")
	}
}

func (d *dockerClient) workloadIDsList(ctx context.Context) ([]string, error) {
	cList, err := d.ContainerList(ctx, dTypes.ContainerListOptions{All: false})
	if err != nil {
		return nil, err

	}

	cont := make([]string, 0, len(cList))
	for _, c := range cList {
		cont = append(cont, c.ID)
	}
	return cont, nil
}

// GetAllInfraContainersPID returns a map that maps container IDs to the PID
// of that container.
func (d *dockerClient) GetAllInfraContainersPID() (map[string]int, error) {
	timeoutCtx, cancel := ctx.WithTimeout(ctx.Background(), 10*time.Second)
	defer cancel()

	cList, err := Client().workloadIDsList(timeoutCtx)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve the container list")
		return nil, err
	}
	pids := map[string]int{}
	for _, contID := range cList {
		cJSON, err := d.ContainerInspect(context.Background(), contID)
		if err != nil {
			continue
		}
		if cJSON.Config == nil || !utils.IsInfraContainer(cJSON.Config.Labels) {
			continue
		}
		if cJSON.State == nil || !cJSON.State.Running {
			continue
		}
		pids[cJSON.ID] = cJSON.State.Pid
	}

	return pids, nil
}

// finishIpvlanInit finishes configuring ipvlan slave device of the given endpoint.
//
// Unfortunately, Docker libnetwork itself moves a netdev to netns of a container
// after the Cilium libnetwork plugin driver has responded to a `JoinEndpoint`
// request. During the move, the netdev qdisc's get flushed by the kernel. Therefore,
// we need to configure the ipvlan slave device in two stages.
//
// Because the function can be called many times for the same container in parallel,
// we need to make the function idempotent. This is achieved by checking
// whether the datapath map has been pinned, which indicates previous
// successful invocation of the function for the same container, before executing
// the configuration stages.
//
// FIXME: Because of the libnetwork limitation mentioned above, we cannot enforce
// policies for an ipvlan slave before a process of a container has started. So,
// this enables a window between the two stages during which ALL container traffic
// is allowed.
func finishIpvlanInit(ep *endpoint.Endpoint, netNsPath string) error {
	var ipvlanIface string

	if netNsPath == "" {
		return fmt.Errorf("netNsPath is empty")
	}

	// Just ignore if the endpoint is dying
	if err := ep.LockAlive(); err != nil {
		return nil
	}
	defer ep.Unlock()

	if ep.IsDatapathMapPinnedLocked() {
		// The datapath map is pinned which implies that the post-initialization
		// for the ipvlan slave has been successfully performed
		return nil
	}

	// To access the netns, `/var/run/docker/netns` has to
	// be bind mounted into the cilium-agent container with
	// the `rshared` option to prevent from leaking netns
	netNs, err := ns.GetNS(netNsPath)
	if err != nil {
		return fmt.Errorf("Unable to open container netns %s: %s", netNsPath, err)
	}

	// Docker doesn't report about interfaces used to connect to
	// container network, so we need to scan all to find the ipvlan slave
	err = netNs.Do(func(ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.Type() == "ipvlan" &&
				strings.HasPrefix(link.Attrs().Name,
					driver.ContainerInterfacePrefix) {
				ipvlanIface = link.Attrs().Name
				break
			}
		}
		if ipvlanIface == "" {
			return fmt.Errorf("ipvlan slave link not found")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("Unable to find ipvlan slave in container netns: %s", err)
	}

	mapFD, mapID, err := connector.SetupIpvlanInRemoteNs(netNs,
		ipvlanIface, ipvlanIface)
	if err != nil {
		return fmt.Errorf("Unable to setup ipvlan slave: %s", err)
	}
	// Do not close the fd too early, as the subsequent pinning would
	// fail due to the map being removed by the kernel
	defer func() {
		unix.Close(mapFD)
	}()

	if err = ep.SetDatapathMapIDAndPinMapLocked(mapID); err != nil {
		return fmt.Errorf("Unable to pin datapath map: %s", err)
	}

	return nil
}
