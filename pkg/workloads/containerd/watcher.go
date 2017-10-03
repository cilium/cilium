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

package containerd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/workloads"

	dTypes "github.com/docker/engine-api/types"
	dTypesEvents "github.com/docker/engine-api/types/events"
	dNetwork "github.com/docker/engine-api/types/network"
	log "github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	syncRateDocker = 30 * time.Second

	maxRetries = 3

	eventQueueBufferSize = 100
)

// containerEvents holds per-container queues for events
type containerEvents struct {
	sync.Mutex
	events map[string]chan dTypesEvents.Message
}

func (ce *containerEvents) enqueueByContainerID(e dTypesEvents.Message) {
	ce.Lock()
	defer ce.Unlock()

	if _, found := ce.events[e.Actor.ID]; !found {
		q := make(chan dTypesEvents.Message, eventQueueBufferSize)
		ce.events[e.Actor.ID] = q
		go processContainerEvents(e.Actor.ID, q)
	}
	ce.events[e.Actor.ID] <- e
}

func (ce *containerEvents) reapEmpty() {
	ce.Lock()
	defer ce.Unlock()

	for id, q := range ce.events {
		if len(q) == 0 {
			close(q)
			delete(ce.events, id)
		}
	}
}

func shortContainerID(id string) string {
	return id[:10]
}

// EnableEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func EnableEventListener() error {
	eventQueue := containerEvents{events: make(map[string]chan dTypesEvents.Message)}
	since := time.Now()
	syncWithRuntime()

	eo := dTypes.EventsOptions{Since: strconv.FormatInt(since.Unix(), 10)}
	r, err := dockerClient.Events(ctx.Background(), eo)
	if err != nil {
		return err
	}

	go listenForDockerEvents(&eventQueue, r)

	// start a go routine which periodically synchronizes containers
	// managed by the local container runtime and checks if any of them
	// need to be managed by Cilium. This is a fall back mechanism in case
	// an event notification has been lost.
	go func() {
		for {
			time.Sleep(syncRateDocker)
			syncWithRuntime()

			log.Debug("Reaping empty event queues")
			eventQueue.reapEmpty()
		}
	}()

	log.Debugf("Started to listen for containerd events")

	return nil
}

// syncWithRuntime is used by the daemon to synchronize changes between Docker and
// Cilium. This includes identities, labels, etc.
func syncWithRuntime() {
	var wg sync.WaitGroup

	// FIXME GH-1662: Must be synchronize with event handler

	cList, err := dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{All: false})
	if err != nil {
		log.Errorf("Failed to retrieve the container list %s", err)
	}
	for _, cont := range cList {
		if ignoredContainer(cont.ID) {
			continue
		}

		wg.Add(1)
		go func(wg *sync.WaitGroup, id string) {
			log.WithFields(log.Fields{
				logfields.ContainerID: shortContainerID(id),
			}).Debug("Periodic synchronization of container")

			handleCreateContainer(id, false)
			wg.Done()
		}(&wg, cont.ID)
	}

	// Wait for all spawned go routines handling container creations to exit
	wg.Wait()
}

func listenForDockerEvents(eventQueue *containerEvents, reader io.ReadCloser) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var e dTypesEvents.Message
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			log.Errorf("Error while unmarshalling event: %+v", e)
		}

		if e.ID != "" {
			log.WithFields(log.Fields{
				"event":               e.Status,
				logfields.ContainerID: shortContainerID(e.ID),
			}).Debug("Queueing container event")
			eventQueue.enqueueByContainerID(e)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("Error while reading events: %+v", err)
	}
}

func processContainerEvents(containerID string, events chan dTypesEvents.Message) {
	for m := range events {
		if m.ID != "" {
			log.WithFields(log.Fields{
				"event":               m.Status,
				logfields.ContainerID: shortContainerID(m.ID),
			}).Debug("Processing event for Container")
			processEvent(m)
		}
	}
}

func processEvent(m dTypesEvents.Message) {
	if m.Type == "container" {
		switch m.Status {
		case "start":
			// A real event overwrites any memory of ignored containers
			stopIgnoringContainer(m.ID)
			handleCreateContainer(m.ID, true)
		case "die":
			workloads.Owner().DeleteEndpoint(endpoint.NewID(endpoint.ContainerIdPrefix, m.ID))
		}
	}
}

func getCiliumEndpointID(cont *dTypes.ContainerJSON) uint16 {
	if cont.NetworkSettings == nil {
		log.WithFields(log.Fields{
			logfields.ContainerID: shortContainerID(cont.ID),
		}).Debug("No network settings included in event")
		return 0
	}

	if ciliumIP := getCiliumIPv6(cont.NetworkSettings.Networks); ciliumIP != nil {
		return ciliumIP.EndpointID()
	}

	log.WithFields(log.Fields{
		logfields.ContainerID: shortContainerID(cont.ID),
	}).Debug("IP address assigned by Cilium could not be derived from container event")

	return 0
}

func getCiliumIPv6(networks map[string]*dNetwork.EndpointSettings) *addressing.CiliumIPv6 {
	for _, contNetwork := range networks {
		if contNetwork == nil {
			continue
		}

		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if !ipv6gw.Equal(nodeaddress.GetIPv6Router()) {
			log.Debugf("Skipping network %s because of gateway mismatch", contNetwork)
			continue
		}
		ip, err := addressing.NewCiliumIPv6(contNetwork.GlobalIPv6Address)
		if err == nil {
			return &ip
		}
	}
	return nil
}

func fetchK8sLabels(dockerLbls map[string]string) (map[string]string, error) {
	if !k8s.IsEnabled() {
		return nil, nil
	}
	ns := k8sDockerLbls.GetPodNamespace(dockerLbls)
	if ns == "" {
		ns = "default"
	}
	podName := k8sDockerLbls.GetPodName(dockerLbls)
	if podName == "" {
		return nil, nil
	}
	log.Debugf("Connecting to kubernetes to retrieve labels for pod %s ns %s", podName, ns)

	result, err := k8s.Client().CoreV1().Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	k8sLabels := result.GetLabels()
	if k8sLabels == nil {
		return nil, nil
	}
	k8sLabels[k8s.PodNamespaceLabel] = ns
	return k8sLabels, nil
}

func getFilteredLabels(allLabels map[string]string) (identityLabels, informationLabels labels.Labels) {
	combinedLabels := labels.Map2Labels(allLabels, labels.LabelSourceContainer)

	// Merge Kubernetes labels into container runtime labels
	if podName := k8sDockerLbls.GetPodName(allLabels); podName != "" {
		k8sNormalLabels, err := fetchK8sLabels(allLabels)
		if err != nil {
			log.Warningf("Error while getting Kubernetes labels: %s", err)
		} else if k8sNormalLabels != nil {
			k8sLbls := labels.Map2Labels(k8sNormalLabels, labels.LabelSourceK8s)
			combinedLabels.MergeLabels(k8sLbls)
		}
	}

	return labels.FilterLabels(combinedLabels)
}

func handleCreateContainer(id string, retry bool) {
	maxTries := 5

	for try := 1; try <= maxTries; try++ {
		var ciliumID uint16

		if try > 1 {
			if retry {
				log.WithFields(log.Fields{
					logfields.ContainerID: shortContainerID(id),
					"retry":               try,
					"maxRetry":            maxTries,
				}).Debug("Waiting for endpoint representing container to appear")
				time.Sleep(time.Duration(try) * time.Second)
			} else {
				break
			}
		}

		dockerContainer, identityLabels, informationLabels, err := retrieveDockerLabels(id)
		if err != nil {
			log.WithFields(log.Fields{
				logfields.ContainerID: shortContainerID(id),
			}).WithError(err).Warning("Unable to inspect container, retrying...")
			continue
		}

		containerName := dockerContainer.Name
		if containerName == "" {
			log.WithFields(log.Fields{
				logfields.ContainerID: shortContainerID(id),
			}).Warning("Container name not set in event from containerd")
		}

		ep := endpointmanager.LookupDockerID(id)
		if ep == nil {
			// Container ID is not yet known; try and find endpoint via
			// the IP address assigned.
			ciliumID = getCiliumEndpointID(dockerContainer)
			if ciliumID != 0 {
				ep = endpointmanager.LookupCiliumID(ciliumID)
			}
		}

		log.WithFields(log.Fields{
			logfields.ContainerID:    shortContainerID(id),
			logfields.EndpointID:     ciliumID,
			"containerName":          containerName,
			logfields.IdentityLabels: identityLabels,
		}).Debug("Trying to associate container with existing endpoint")

		if ep == nil {
			// Endpoint does not exist yet. This indicates that the
			// orchestration system has not requested us to handle
			// networking for this container yet (or never will).
			// We will retry a couple of times to wait for this to
			// happen.
			continue
		}

		ep.SetContainerID(id)

		if dockerContainer.NetworkSettings != nil {
			id := dockerContainer.NetworkSettings.EndpointID
			if id != "" {
				ep.SetDockerEndpointID(id)
			}
		}

		// Docker appends '/' to container names.
		ep.SetContainerName(strings.Trim(containerName, "/"))

		// In Kubernetes mode, attempt to retrieve pod name stored in
		// container runtime label
		//
		// FIXME: Abstract via interface so other workload types can
		// implement this
		if k8s.IsEnabled() {
			if dockerContainer.Config != nil {
				podNamespace := k8sDockerLbls.GetPodNamespace(dockerContainer.Config.Labels)
				podName := k8sDockerLbls.GetPodName(dockerContainer.Config.Labels)
				ep.SetPodName(fmt.Sprintf("%s:%s", podNamespace, podName))
			}
		}

		// Update map allowing to lookup endpoint by endpoint
		// attributes with new attributes set on endpoint
		endpointmanager.UpdateReferences(ep)

		err = workloads.Owner().EndpointLabelsUpdate(ep, identityLabels, informationLabels)
		if err != nil {
			log.WithFields(log.Fields{
				logfields.EndpointID:  ep.StringID(),
				logfields.ContainerID: shortContainerID(id),
			}).Warning(err.Error())
		}
		return
	}

	startIgnoringContainer(id)

	log.WithFields(log.Fields{
		logfields.ContainerID: shortContainerID(id),
	}).Info("No endpoint appeared representing the container. Likely managed by other plugin")
}

// retrieveDockerLabels returns the metadata for the container with ID dockerID,
// and two sets of labels: the labels that are utilized in computing the security
// identity for an endpoint, and the set of labels that are not utilized in
// computing the security identity for an endpoint.
func retrieveDockerLabels(dockerID string) (*dTypes.ContainerJSON, labels.Labels, labels.Labels, error) {
	dockerCont, err := dockerClient.ContainerInspect(ctx.Background(), dockerID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to inspect container '%s': %s", dockerID, err)
	}

	newLabels := labels.Labels{}
	informationLabels := labels.Labels{}
	if dockerCont.Config != nil {
		newLabels, informationLabels = getFilteredLabels(dockerCont.Config.Labels)
	}

	return &dockerCont, newLabels, informationLabels, nil
}

// IgnoreRunningContainers checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func IgnoreRunningContainers() {
	conts, err := dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{})
	if err != nil {
		return
	}
	for _, cont := range conts {
		log.Infof("Adding running container %q to the list of ignored containers", cont.ID)
		startIgnoringContainer(cont.ID)
		if cont.NetworkSettings == nil {
			continue
		}
		cIP := getCiliumIPv6(cont.NetworkSettings.Networks)
		if cIP == nil {
			continue
		}
		if err := ipam.AllocateIP(cIP.IP()); err != nil {
			continue
		}
		// TODO Release this address when the ignored container leaves
		log.Infof("Found container running with potential "+
			"collision IP address %q, adding to the list "+
			"of allocated IPs", cIP.IP().String())
	}
}
