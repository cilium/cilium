// Copyright 2016-2018 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/workloads"

	dTypes "github.com/docker/engine-api/types"
	dTypesEvents "github.com/docker/engine-api/types/events"
	dNetwork "github.com/docker/engine-api/types/network"
	"github.com/sirupsen/logrus"
	ctx "golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	syncRateDocker = 30 * time.Second

	eventQueueBufferSize = 100
)

func shortContainerID(id string) string {
	return id[:10]
}

// EnableEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func EnableEventListener() error {
	if dockerClient == nil {
		return nil
	}

	ws := newWatcherState(eventQueueBufferSize)
	// start a go routine which periodically synchronizes containers
	// managed by the local container runtime and checks if any of them
	// need to be managed by Cilium. This is a fall back mechanism in case
	// an event notification has been lost.
	// Note: We do the sync before the first sleep
	go func(state *watcherState) {
		for {
			state.reapEmpty()
			state.syncWithRuntime()
			time.Sleep(syncRateDocker)
		}
	}(ws)

	since := time.Now()
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(since.Unix(), 10)}
	r, err := dockerClient.Events(ctx.Background(), eo)
	if err != nil {
		return err
	}

	go listenForDockerEvents(ws, r)

	log.Debug("Started to listen for containerd events")
	return nil
}

func listenForDockerEvents(ws *watcherState, reader io.ReadCloser) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		metrics.SetTSValue(metrics.EventTSContainerd, time.Now())

		var e dTypesEvents.Message
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			log.WithError(err).Error("Error while unmarshalling event")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if e.ID != "" {
			log.WithFields(logrus.Fields{
				"event":               e.Status,
				logfields.ContainerID: shortContainerID(e.ID),
			}).Debug("Queueing container event")
			ws.enqueueByContainerID(e.ID, &e)
		}
	}

	if err := scanner.Err(); err != nil {
		log.WithError(err).Error("Error while reading events")
	}
}

func processContainerEvents(events chan dTypesEvents.Message) {
	for m := range events {
		if m.ID != "" {
			log.WithFields(logrus.Fields{
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
	scopedLog := log.WithField(logfields.ContainerID, shortContainerID(cont.ID))

	if cont.NetworkSettings == nil {
		scopedLog.Debug("No network settings included in event")
		return 0
	}

	if ciliumIP := getCiliumIPv6(cont.NetworkSettings.Networks); ciliumIP != nil {
		return ciliumIP.EndpointID()
	}

	scopedLog.Debug("IP address assigned by Cilium could not be derived from container event")

	return 0
}

func getCiliumIPv6(networks map[string]*dNetwork.EndpointSettings) *addressing.CiliumIPv6 {
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
	log.WithFields(logrus.Fields{
		logfields.K8sNamespace: ns,
		logfields.K8sPodName:   podName,
	}).Debug("Connecting to k8s to retrieve labels for pod in ns")

	result, err := k8s.Client().CoreV1().Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Also get all labels from the namespace where the pod is running
	k8sNs, err := k8s.Client().CoreV1().Namespaces().Get(ns, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	k8sLabels := result.GetLabels()
	if k8sLabels == nil {
		k8sLabels = map[string]string{}
	}
	for k, v := range k8sNs.GetLabels() {
		k8sLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
	}
	k8sLabels[k8sConst.PodNamespaceLabel] = ns
	return k8sLabels, nil
}

func getFilteredLabels(allLabels map[string]string) (identityLabels, informationLabels labels.Labels) {
	combinedLabels := labels.Map2Labels(allLabels, labels.LabelSourceContainer)

	// Merge Kubernetes labels into container runtime labels
	if podName := k8sDockerLbls.GetPodName(allLabels); podName != "" {
		k8sNormalLabels, err := fetchK8sLabels(allLabels)
		if err != nil {
			log.WithError(err).Warn("Error while getting Kubernetes labels")
		} else if k8sNormalLabels != nil {
			k8sLbls := labels.Map2Labels(k8sNormalLabels, labels.LabelSourceK8s)
			combinedLabels.MergeLabels(k8sLbls)
		}
	}

	return labels.FilterLabels(combinedLabels)
}

func handleCreateContainer(id string, retry bool) {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.ContainerID: shortContainerID(id),
		fieldMaxRetry:         workloads.EndpointCorrelationMaxRetries,
	})

	for try := 1; try <= workloads.EndpointCorrelationMaxRetries; try++ {
		var ciliumID uint16

		if try > 1 {
			if retry {
				scopedLog.WithField("retry", try).Debug("Waiting for endpoint representing container to appear")
				time.Sleep(workloads.EndpointCorrelationSleepTime(try))
			} else {
				break
			}
		}

		dockerContainer, identityLabels, informationLabels, err := retrieveDockerLabels(id)
		if err != nil {
			scopedLog.WithError(err).WithField("retry", try).Warn("Unable to inspect container, retrying...")
			continue
		}

		containerName := dockerContainer.Name
		if containerName == "" {
			scopedLog.WithField("retry", try).Warn("Container name not set in event from containerd")
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

		scopedLog.WithFields(logrus.Fields{
			logfields.EndpointID:     ciliumID,
			"retry":                  try,
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
				ep.SetK8sNamespace(k8sDockerLbls.GetPodNamespace(dockerContainer.Config.Labels))
				ep.SetK8sPodName(k8sDockerLbls.GetPodName(dockerContainer.Config.Labels))
			}
		}

		// Update map allowing to lookup endpoint by endpoint
		// attributes with new attributes set on endpoint
		endpointmanager.UpdateReferences(ep)

		ep.UpdateLabels(workloads.Owner(), identityLabels, informationLabels)
		return
	}

	startIgnoringContainer(id)

	scopedLog.Info("No request received to manage networking for container")
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
	if dockerClient == nil {
		return
	}

	conts, err := dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{})
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
		cIP := getCiliumIPv6(cont.NetworkSettings.Networks)
		if cIP == nil {
			continue
		}
		if err := ipam.AllocateIP(cIP.IP()); err != nil {
			continue
		}
		// TODO Release this address when the ignored container leaves
		scopedLog.WithFields(logrus.Fields{
			logfields.IPAddr: cIP.IP(),
		}).Info("Found container running with potential " +
			"collision IP address, adding to the list " +
			"of allocated IPs")
	}
}
