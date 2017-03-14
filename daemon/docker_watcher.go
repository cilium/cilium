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
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"

	dTypes "github.com/docker/engine-api/types"
	dTypesEvents "github.com/docker/engine-api/types/events"
	ctx "golang.org/x/net/context"
	k8sDockerLbls "k8s.io/client-go/1.5/pkg/kubelet/types"
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

func (d *Daemon) SyncDocker(wg *sync.WaitGroup) {
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
			d.handleCreateContainer(id)
			wg.Done()
		}(wg, cont.ID)
	}
}

func (d *Daemon) EnableDockerSync() {
	var wg sync.WaitGroup
	for {
		d.SyncDocker(&wg)
		wg.Wait()
		time.Sleep(syncRateDocker)
	}
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
			d.handleCreateContainer(m.ID)
		case "die":
			d.deleteContainer(m.ID)
		}
	}
}

func getCiliumEndpointID(cont *dTypes.ContainerJSON, gwIP *addressing.NodeAddress) uint16 {
	for _, contNetwork := range cont.NetworkSettings.Networks {
		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if ipv6gw.Equal(gwIP.IPv6Address.IP()) {
			ip, err := addressing.NewCiliumIPv6(contNetwork.GlobalIPv6Address)
			if err == nil {
				return ip.EndpointID()
			}
		}
	}

	return 0
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

	result, err := d.k8sClient.Pods(ns).Get(podName)
	if err != nil {
		return nil, err
	}
	k8sLabels := result.GetLabels()
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

func (d *Daemon) retrieveWorkingContainerCopy(id string) (types.Container, bool) {
	d.containersMU.RLock()
	defer d.containersMU.RUnlock()

	if c, ok := d.containers[id]; ok {
		return *c, true
	} else {
		return types.Container{}, false
	}
}

func createContainer(dc *dTypes.ContainerJSON, l labels.Labels) types.Container {
	return types.Container{
		ContainerJSON: *dc,
		OpLabels: labels.OpLabels{
			Custom:        labels.Labels{},
			Disabled:      labels.Labels{},
			Orchestration: l.DeepCopy(),
		},
	}
}

func (d *Daemon) handleCreateContainer(id string) {
	log.Debugf("Processing create event for docker container %s", id)

	maxTries := 5

	for try := 1; try <= maxTries; try++ {
		if try > 1 {
			log.Debugf("Waiting for container %s to appear as endpoint [%d/%d]",
				id, try, maxTries)
			time.Sleep(time.Duration(try) * time.Second)
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

		d.endpointsMU.Lock()
		ep := d.lookupDockerID(id)
		if ep == nil {
			// container id is yet unknown, try and find endpoint via
			// the IP address assigned.
			cid := getCiliumEndpointID(dockerContainer, d.conf.NodeAddress)
			if cid != 0 {
				ep = d.lookupCiliumEndpoint(cid)
				if ep != nil {
					// Associate container id with endpoint
					ep.DockerID = id
					d.linkContainerID(ep)
				}
			}
		}

		d.endpointsMU.Unlock()
		if ep == nil {
			// Endpoint does not exist yet. This indicates that the
			// orchestration system has not requested us to handle
			// networking for this container yet (or never will). We
			// will retry a couple of times to wait for this to
			// happen.
			continue
		}

		containerCopy, ok := d.retrieveWorkingContainerCopy(id)
		if ok {
			if !updateOrchLabels(&containerCopy, lbls) {
				log.Debugf("No changes to orch labels, ignoring")
				return
			}
		} else {
			containerCopy = createContainer(dockerContainer, lbls)
		}

		identity, err := d.updateContainerIdentity(&containerCopy)
		if err != nil {
			log.Warningf("unable to update identity of container %s: %s", id, err)
			return
		}

		// FIXME:

		d.endpointsMU.Lock()
		ep = d.lookupDockerID(id)
		if ep == nil {
			d.endpointsMU.Unlock()
			log.Warningf("endpoint disappeared while processing event for %s, ignoring", id)
			return
		}

		d.containersMU.Lock()

		// If the container ID was known and found before, check if it still
		// exists, it may have disappared while we gave up the containers
		// lock to create/udpate the identity.
		if ok && d.containers[ep.DockerID] == nil {
			// endpoint is around but container id was removed, likely
			// a bug.
			//
			// FIXME: Disconnect endpoint?
			d.endpointsMU.Unlock()
			d.containersMU.Unlock()
			log.Errorf("BUG: unrefered container %s with endpoint %d present",
				id, ep.ID)
			return
		}

		// Commit label changes to container
		d.containers[ep.DockerID] = &containerCopy

		d.setEndpointIdentity(ep, containerCopy.ID, dockerEpID, identity)
		if err := ep.Regenerate(d); err != nil {
			// FIXME: Disconnect endpoint?
		}

		d.endpointsMU.Unlock()
		d.containersMU.Unlock()

		// FIXME: Does this rebuild epID twice?
		d.triggerPolicyUpdates([]policy.NumericIdentity{identity.ID})
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

func updateOrchLabels(c *types.Container, l labels.Labels) bool {
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
				tmp := *v
				log.Debugf("Assigning orchestration label %+v", tmp)
				c.OpLabels.Orchestration[k] = &tmp
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
