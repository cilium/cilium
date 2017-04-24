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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	dTypes "github.com/docker/engine-api/types"
	dTypesEvents "github.com/docker/engine-api/types/events"
	dNetwork "github.com/docker/engine-api/types/network"
	ctx "golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	syncRateDocker = time.Duration(30 * time.Second)

	maxRetries = 3
)

// EnableDockerEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func (d *Daemon) EnableDockerEventListener(since time.Time) error {
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(since.Unix(), 10)}
	r, err := d.dockerClient.Events(ctx.Background(), eo)
	if err != nil {
		return err
	}
	log.Debugf("Listening for docker events")
	go d.listenForDockerEvents(r)
	return nil
}

func (d *Daemon) SyncDocker() {
	var wg sync.WaitGroup

	cList, err := d.dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{All: false})
	if err != nil {
		log.Errorf("Failed to retrieve the container list %s", err)
	}
	for _, cont := range cList {
		if d.IgnoredContainer(cont.ID) {
			continue
		}

		wg.Add(1)
		go func(wg *sync.WaitGroup, id string) {
			d.handleCreateContainer(id, false)
			wg.Done()
		}(&wg, cont.ID)
	}

	// Wait for all spawned go routines handling container creations to exit
	wg.Wait()
}

func (d *Daemon) backgroundContainerSync() {
	for {
		d.SyncDocker()
		time.Sleep(syncRateDocker)
	}
}

// RunBackgroundContainerSync spawns a go routine which periodically
// synchronizes containers managed by the local container runtime and
// checks if any of them need to be managed by Cilium. This is a fall
// back mechanism in case an event notification has been lost.
func (d *Daemon) RunBackgroundContainerSync() {
	go d.backgroundContainerSync()
}

func (d *Daemon) listenForDockerEvents(reader io.ReadCloser) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var e dTypesEvents.Message
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			log.Errorf("Error while unmarshalling event: %+v", e)
		}
		log.Debugf("Processing an event %+v", e)
		go d.processEvent(e)
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while reading events: %+v", err)
	}
}

func (d *Daemon) processEvent(m dTypesEvents.Message) {
	if m.Type == "container" {
		switch m.Status {
		case "start":
			// A real event overwrites any memory of ignored containers
			d.StopIgnoringContainer(m.ID)
			d.handleCreateContainer(m.ID, true)
		case "die":
			d.deleteContainer(m.ID)
		}
	}
}

func getCiliumEndpointID(cont *dTypes.ContainerJSON, gwIP *addressing.NodeAddress) uint16 {
	if cont.NetworkSettings == nil {
		return 0
	}

	if ciliumIP := getCiliumIPv6(cont.NetworkSettings.Networks, gwIP); ciliumIP != nil {
		return ciliumIP.EndpointID()
	}
	return 0
}

func getCiliumIPv6(networks map[string]*dNetwork.EndpointSettings, gwIP *addressing.NodeAddress) *addressing.CiliumIPv6 {
	for _, contNetwork := range networks {
		if contNetwork == nil {
			continue
		}
		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if !ipv6gw.Equal(gwIP.IPv6Address.IP()) {
			continue
		}
		ip, err := addressing.NewCiliumIPv6(contNetwork.GlobalIPv6Address)
		if err == nil {
			return &ip
		}
	}
	return nil
}

func (d *Daemon) fetchK8sLabels(dockerLbls map[string]string) (map[string]string, error) {
	if !d.conf.IsK8sEnabled() {
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

	result, err := d.k8sClient.Pods(ns).Get(podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	k8sLabels := result.GetLabels()
	if k8sLabels == nil {
		return nil, nil
	}
	k8sLabels[common.K8sPodNamespaceLabel] = ns
	return k8sLabels, nil
}

func (d *Daemon) getFilteredLabels(allLabels map[string]string) labels.Labels {
	var ciliumLabels, k8sLabels, k8sSpecialLabels labels.Labels
	if podName := k8sDockerLbls.GetPodName(allLabels); podName != "" {
		k8sNormalLabels, err := d.fetchK8sLabels(allLabels)
		if err != nil {
			log.Warningf("Error while getting kubernetes labels: %s", err)
		} else if k8sNormalLabels != nil {
			k8sLabels = labels.Map2Labels(k8sNormalLabels, common.K8sLabelSource)

			// Transform all labels "k8s-app" and "version" to "io.cilium.k8s.k8s-app"
			// and  "io.cilium.k8s.version"
			d.conf.ValidLabelPrefixesMU.RLock()
			k8sSpecialLabels = d.conf.ValidK8sLabelPrefixes.FilterLabels(k8sLabels)
			d.conf.ValidLabelPrefixesMU.RUnlock()
			k8sSpecialLabels = k8sSpecialLabels.AppendPrefixInKey(common.K8sLabelPrefix)
			log.Debug("Special labels %s", k8sSpecialLabels)
		}
	}

	ciliumLabels = labels.Map2Labels(allLabels, common.CiliumLabelSource)

	ciliumLabels.MergeLabels(k8sLabels)

	d.conf.ValidLabelPrefixesMU.RLock()
	normalLabels := d.conf.ValidLabelPrefixes.FilterLabels(ciliumLabels)
	d.conf.ValidLabelPrefixesMU.RUnlock()

	normalLabels.MergeLabels(k8sSpecialLabels)
	return normalLabels
}

func (d *Daemon) handleCreateContainer(id string, retry bool) {
	log.Debugf("Processing create event for docker container %s", id)

	maxTries := 5

	for try := 1; try <= maxTries; try++ {
		if try > 1 {
			if retry {
				log.Debugf("Waiting for container %s to appear as endpoint [%d/%d]",
					id, try, maxTries)
				time.Sleep(time.Duration(try) * time.Second)
			} else {
				return
			}
		}

		dockerContainer, lbls, err := d.retrieveDockerLabels(id)
		if err != nil {
			log.Warningf("unable to inspect container %s, retrying later (%s)", id, err)
			continue
		}

		dockerEpID := ""
		if dockerContainer.NetworkSettings != nil {
			dockerEpID = dockerContainer.NetworkSettings.EndpointID
		}

		d.endpointsMU.RLock()
		ep := d.lookupDockerID(id)
		d.endpointsMU.RUnlock()
		if ep == nil {
			// container id is yet unknown, try and find endpoint via
			// the IP address assigned.
			cid := getCiliumEndpointID(dockerContainer, d.conf.NodeAddress)
			if cid != 0 {
				d.endpointsMU.Lock()
				ep = d.lookupCiliumEndpoint(cid)
				if ep != nil {
					// Associate container id with endpoint
					ep.Mutex.Lock()
					ep.DockerID = id
					ep.Mutex.Unlock()
					d.linkContainerID(ep)
				}
				d.endpointsMU.Unlock()
			}
		}

		if ep == nil {
			// Endpoint does not exist yet. This indicates that the
			// orchestration system has not requested us to handle
			// networking for this container yet (or never will). We
			// will retry a couple of times to wait for this to
			// happen.
			continue
		}

		var orchLabelsModified bool
		d.containersMU.RLock()
		cont, ok := d.containers[id]
		d.containersMU.RUnlock()
		if ok {
			cont.Mutex.Lock()
			if orchLabelsModified = updateOrchLabels(cont, lbls); !orchLabelsModified {
				log.Debugf("No changes to orch labels, ignoring")
			}
		} else {
			cont = container.NewContainer(dockerContainer, lbls)
			cont.Mutex.Lock()
		}

		// It's mandatory to update the container in its label otherwise
		// the label will be considered unused.
		identity, newHash, err := d.updateContainerIdentity(cont.ID, cont.LabelsHash, &cont.OpLabels)
		if err != nil {
			cont.Mutex.Unlock()
			log.Warningf("unable to update identity of container %s: %s", id, err)
			return
		}
		cont.LabelsHash = newHash
		cID := cont.ID
		cont.Mutex.Unlock()

		if ok && !orchLabelsModified {
			return
		}

		d.endpointsMU.RLock()
		ep = d.lookupDockerID(id)
		d.endpointsMU.RUnlock()
		if ep == nil {
			log.Warningf("endpoint disappeared while processing event for %s, ignoring", id)
			return
		}
		ep.Mutex.RLock()
		epDockerID := ep.DockerID
		epID := ep.ID
		ep.Mutex.RUnlock()

		d.containersMU.Lock()

		// If the container ID was known and found before, check if it still
		// exists, it may have disappared while we gave up the containers
		// lock to create/udpate the identity.
		if ok && d.containers[epDockerID] == nil {
			d.containersMU.Unlock()
			// endpoint is around but container id was removed, likely
			// a bug.
			//
			// FIXME: Disconnect endpoint?
			log.Errorf("BUG: unrefered container %s with endpoint %d present",
				id, epID)
			return
		}

		// Commit label changes to container
		d.containers[epDockerID] = cont
		d.containersMU.Unlock()

		d.SetEndpointIdentity(ep, cID, dockerEpID, identity)
		ep.Regenerate(d)

		// FIXME: Does this rebuild epID twice?
		d.TriggerPolicyUpdates([]policy.NumericIdentity{identity.ID})
		return
	}

	d.StartIgnoringContainer(id)
	log.Infof("Container %s did not appear as endpoint. Likely managed by other plugin", id)
}

func (d *Daemon) retrieveDockerLabels(dockerID string) (*dTypes.ContainerJSON, labels.Labels, error) {
	dockerCont, err := d.dockerClient.ContainerInspect(ctx.Background(), dockerID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to inspect container '%s': %s", dockerID, err)
	}

	newLabels := labels.Labels{}
	if dockerCont.Config != nil {
		newLabels = d.getFilteredLabels(dockerCont.Config.Labels)
	}

	return &dockerCont, newLabels, nil
}

func updateOrchLabels(c *container.Container, l labels.Labels) bool {
	changed := false

	c.OpLabels.Orchestration.MarkAllForDeletion()
	c.OpLabels.Disabled.MarkAllForDeletion()

	for k, v := range l {
		if c.OpLabels.Disabled[k] != nil {
			c.OpLabels.Disabled[k].DeletionMark = false
		} else {
			if c.OpLabels.Orchestration[k] != nil {
				c.OpLabels.Orchestration[k].DeletionMark = false
			} else {
				tmp := v.DeepCopy()
				log.Debugf("Assigning orchestration label %+v", tmp)
				c.OpLabels.Orchestration[k] = tmp
				changed = true
			}
		}
	}

	if c.OpLabels.Orchestration.DeleteMarked() || c.OpLabels.Disabled.DeleteMarked() {
		changed = true
	}

	return changed
}

func (d *Daemon) deleteContainer(dockerID string) {
	log.Debugf("Processing deletion event for docker container %s", dockerID)

	d.containersMU.Lock()
	if container, ok := d.containers[dockerID]; ok {
		sha256sum := container.OpLabels.Enabled().SHA256Sum()
		if err := d.DeleteIdentityBySHA256(sha256sum, dockerID); err != nil {
			log.Errorf("Error while deleting labels (SHA256SUM:%s) %+v: %s",
				sha256sum, container.OpLabels.Enabled(), err)
		}

		delete(d.containers, dockerID)
	}
	d.containersMU.Unlock()

	d.DeleteEndpoint(endpoint.NewID(endpoint.ContainerIdPrefix, dockerID))
}

// IgnoreRunningContainers checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func (d *Daemon) IgnoreRunningContainers() {
	conts, err := d.dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{})
	if err != nil {
		return
	}
	for _, cont := range conts {
		log.Infof("Adding running container %q to the list of ignored containers", cont.ID)
		d.StartIgnoringContainer(cont.ID)
		if cont.NetworkSettings == nil {
			continue
		}
		cIP := getCiliumIPv6(cont.NetworkSettings.Networks, d.conf.NodeAddress)
		if cIP == nil {
			continue
		}
		if err := d.AllocateIP(cIP.IP()); err != nil {
			continue
		}
		// TODO Release this address when the ignored container leaves
		log.Infof("Found container running with potential "+
			"collision IP address %q, adding to the list "+
			"of allocated IPs", cIP.IP().String())
	}
}
