//
// Copyright 2016 Authors of Cilium
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
package daemon

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
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

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
func (d *Daemon) EnableDockerEventListener() error {
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(time.Now().Unix(), 10)}
	r, err := d.dockerClient.Events(ctx.Background(), eo)
	if err != nil {
		return err
	}

	d.EnableDockerSync(true)

	log.Debugf("Listening for docker events")
	go d.listenForEvents(r)
	return nil
}

func (d *Daemon) EnableDockerSync(once bool) {
	var wg sync.WaitGroup
	for {
		cList, err := d.dockerClient.ContainerList(ctx.Background(), dTypes.ContainerListOptions{All: false})
		if err != nil {
			log.Errorf("Failed to retrieve the container list %s", err)
		}
		for _, cont := range cList {
			wg.Add(1)
			go func(wg *sync.WaitGroup, id string) {
				d.createContainer(id)
				wg.Done()
			}(&wg, cont.ID)
		}

		if once {
			return
		}
		wg.Wait()
		time.Sleep(syncRateDocker)
	}
}

func (d *Daemon) listenForEvents(reader io.ReadCloser) {
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
			d.createContainer(m.ID)
		case "die":
			d.deleteContainer(m.ID)
		}
	}
}

func getCiliumEndpointID(cont dTypes.ContainerJSON, gwIP *addressing.NodeAddress) *uint16 {
	for _, contNetwork := range cont.NetworkSettings.Networks {
		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if ipv6gw.Equal(gwIP.IPv6Address.IP()) {
			ip, err := addressing.NewCiliumIPv6(contNetwork.GlobalIPv6Address)
			if err == nil {
				id := ip.EndpointID()
				return &id
			}
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

	result, err := d.k8sClient.Pods(ns).Get(podName)
	if err != nil {
		return nil, err
	}
	k8sLabels := result.GetLabels()
	k8sLabels[common.K8sPodNamespaceLabel] = ns
	return k8sLabels, nil
}

func (d *Daemon) getFilteredLabels(allLabels map[string]string) types.Labels {
	var ciliumLabels, k8sLabels types.Labels
	if podName := k8sDockerLbls.GetPodName(allLabels); podName != "" {
		k8sNormalLabels, err := d.fetchK8sLabels(allLabels)
		if err != nil {
			log.Warningf("Error while getting kubernetes labels: %s", err)
		} else if k8sNormalLabels != nil {
			k8sLabels = types.Map2Labels(k8sNormalLabels, common.K8sLabelSource)
		}
	}

	ciliumLabels = types.Map2Labels(allLabels, common.CiliumLabelSource)

	ciliumLabels.MergeLabels(k8sLabels)

	d.conf.ValidLabelPrefixesMU.RLock()
	defer d.conf.ValidLabelPrefixesMU.RUnlock()
	return d.conf.ValidLabelPrefixes.FilterLabels(ciliumLabels)
}

func (d *Daemon) createContainer(dockerID string) {
	log.Debugf("Processing create event for docker container %s", dockerID)

	d.containersMU.Lock()
	if isNewContainer, container, err := d.updateProbeLabels(dockerID); err != nil {
		d.containersMU.Unlock()
		log.Errorf("%s", err)
	} else {
		d.containersMU.Unlock()
		if err := d.updateContainer(container, isNewContainer); err != nil {
			log.Errorf("%s", err)
		}
	}
}

func (d *Daemon) updateProbeLabels(dockerID string) (bool, *types.Container, error) {
	dockerCont, err := d.dockerClient.ContainerInspect(ctx.Background(), dockerID)
	if err != nil {
		return false, nil, fmt.Errorf("Error while inspecting container '%s': %s", dockerID, err)
	}

	ciliumLabels := types.Labels{}
	if dockerCont.Config != nil {
		log.Debugf("Read docker labels %+v", dockerCont.Config.Labels)
		ciliumLabels = d.getFilteredLabels(dockerCont.Config.Labels)
	}
	log.Debugf("Using filtered labels %+v", ciliumLabels)

	return d.updateOperationalLabels(dockerID, dockerCont, ciliumLabels, true)
}

func (d *Daemon) updateUserLabels(dockerID string, labels types.Labels) (bool, *types.Container, error) {
	dockerCont, err := d.dockerClient.ContainerInspect(ctx.Background(), dockerID)
	if err != nil {
		return false, nil, fmt.Errorf("Error while inspecting container '%s': %s", dockerID, err)
	}
	return d.updateOperationalLabels(dockerID, dockerCont, labels, false)
}

func (d *Daemon) updateOperationalLabels(dockerID string, dockerCont dTypes.ContainerJSON, newLabels types.Labels, isProbe bool) (bool, *types.Container, error) {
	isNewContainer := false
	var (
		cont           types.Container
		epLabelsSHA256 string
	)

	if ciliumContainer, ok := d.containers[dockerID]; !ok {
		isNewContainer = true
		cont = types.Container{
			ContainerJSON: dockerCont,
			OpLabels: types.OpLabels{
				AllLabels:      newLabels.DeepCopy(),
				UserLabels:     types.Labels{},
				ProbeLabels:    newLabels.DeepCopy(),
				EndpointLabels: newLabels.DeepCopy(),
			},
			NRetries: 0,
		}
	} else {
		if ciliumContainer.NRetries > maxRetries {
			epSHA256Sum, err := ciliumContainer.OpLabels.EndpointLabels.SHA256Sum()
			if err != nil {
				log.Errorf("Error calculating SHA256Sum of labels %+v: %s", ciliumContainer.OpLabels.EndpointLabels, err)
			}
			d.DeleteLabelsBySHA256(epSHA256Sum, ciliumContainer.ID)
			return isNewContainer, nil, nil
		}
		ep, err := d.EndpointGetByDockerID(ciliumContainer.ID)
		if err == nil && ep == nil {
			ciliumContainer.NRetries++
		} else {
			ciliumContainer.NRetries = 0
		}

		newLabelsSHA256, err := newLabels.SHA256Sum()
		if err != nil {
			log.Errorf("Error calculating SHA256Sum of labels %+v: %s", newLabels, err)
		}

		if isProbe {
			probeLabelsSHA256, err := ciliumContainer.OpLabels.ProbeLabels.SHA256Sum()
			if err != nil {
				log.Errorf("Error calculating SHA256Sum of labels %+v: %s", ciliumContainer.OpLabels.ProbeLabels, err)
			}
			if probeLabelsSHA256 != newLabelsSHA256 {
				isNewContainer = true
				epLabelsSHA256, err = ciliumContainer.OpLabels.EndpointLabels.SHA256Sum()
				if err != nil {
					log.Errorf("Error calculating SHA256Sum of labels %+v: %s", ciliumContainer.OpLabels.EndpointLabels, err)
				}
				// probe labels have changed
				// we need to find out which labels were deleted and added
				deletedLabels := ciliumContainer.OpLabels.ProbeLabels.DeepCopy()
				for k, v := range newLabels {
					if ciliumContainer.OpLabels.ProbeLabels[k] == nil {
						tmpLbl1 := *v
						tmpLbl2 := *v
						ciliumContainer.OpLabels.AllLabels[k] = &tmpLbl1
						ciliumContainer.OpLabels.EndpointLabels[k] = &tmpLbl2
					} else {
						delete(deletedLabels, k)
					}
				}

				for k := range deletedLabels {
					delete(ciliumContainer.OpLabels.AllLabels, k)
					delete(ciliumContainer.OpLabels.EndpointLabels, k)
				}
			}
		} else {
			// If it is not probe then all newLabels will be applied
			epLabelsSHA256, err = ciliumContainer.OpLabels.EndpointLabels.SHA256Sum()
			if err != nil {
				log.Errorf("Error calculating SHA256Sum of labels %+v: %s", ciliumContainer.OpLabels.EndpointLabels, err)
			}
			if epLabelsSHA256 != newLabelsSHA256 {
				isNewContainer = true
				ciliumContainer.OpLabels.EndpointLabels = newLabels
			}
		}
		cont = types.Container{
			ContainerJSON: dockerCont,
			OpLabels:      ciliumContainer.OpLabels,
			NRetries:      ciliumContainer.NRetries,
		}
	}

	if isNewContainer {
		if err := d.DeleteLabelsBySHA256(epLabelsSHA256, dockerID); err != nil {
			log.Errorf("Error while deleting old labels (%+v) of container %s: %s", epLabelsSHA256, dockerID, err)
		}
	}

	d.containers[dockerID] = &cont
	contCpy := cont

	return isNewContainer, &contCpy, nil
}

func (d *Daemon) updateContainer(container *types.Container, isNewContainer bool) error {
	if container == nil {
		return nil
	}

	dockerID := container.ID

	secCtxlabels, isNewLabel, err := d.PutLabels(container.OpLabels.EndpointLabels, dockerID)
	if err != nil {
		return fmt.Errorf("Error while getting labels ID: %s", err)
	}

	ciliumID := getCiliumEndpointID(container.ContainerJSON, d.conf.NodeAddress)
	var dockerEPID string
	if container.ContainerJSON.NetworkSettings != nil {
		dockerEPID = container.ContainerJSON.NetworkSettings.EndpointID
	}

	try := 1
	maxTries := 5
	var ep *types.Endpoint
	for try <= maxTries {
		if ep = d.setEndpointSecLabel(ciliumID, dockerID, dockerEPID, secCtxlabels); ep != nil {
			break
		}
		if container.IsDockerOrInfracontainer() {
			log.Debugf("Waiting for orchestration system to request networking for container %s... [%d/%d]", dockerID, try, maxTries)
		}
		time.Sleep(time.Duration(try) * time.Second)
		try++
	}
	if try >= maxTries {
		if container.IsDockerOrInfracontainer() {
			return fmt.Errorf("No manage request in time, container %s is likely managed by other networking plugin.", dockerID)
		}
		return nil
	}
	if isNewContainer {
		if err = d.createBPFMAPs(ep.ID); err != nil {
			return fmt.Errorf("Unable to create & attach BPF programs for container %s: %s", dockerID, err)
		}
	}

	// Perform the policy map updates after programs have been created
	if isNewLabel || isNewContainer {
		d.triggerPolicyUpdates([]uint32{secCtxlabels.ID})
	}

	log.Infof("Assigned security context %d to container %s", secCtxlabels.ID, dockerID)

	return nil
}

func (d *Daemon) deleteContainer(dockerID string) {
	log.Debugf("Processing deletion event for docker container %s", dockerID)

	d.containersMU.Lock()
	if container, ok := d.containers[dockerID]; ok {
		ep, err := d.EndpointGetByDockerID(dockerID)
		if err != nil {
			log.Warningf("Error while getting endpoint by docker ID: %s", err)
		}

		sha256sum, err := container.OpLabels.EndpointLabels.SHA256Sum()
		if err != nil {
			log.Errorf("Error while creating SHA256Sum for labels %+v: %s", container.OpLabels.EndpointLabels, err)
		}

		if err := d.DeleteLabelsBySHA256(sha256sum, dockerID); err != nil {
			log.Errorf("Error while deleting labels (SHA256SUM:%s) %+v: %s", sha256sum, container.OpLabels.EndpointLabels, err)
		}

		delete(d.containers, dockerID)

		if ep != nil {
			d.EndpointLeave(ep.ID)
			var ipamType ipam.IPAMType
			if ep.IsCNI() {
				ipamType = ipam.CNIIPAMType
			} else {
				ipamType = ipam.LibnetworkIPAMType
			}

			if d.conf.IPv4Enabled {
				ipv4 := ep.IPv4.IP()
				if err := d.ReleaseIP(ipamType, ipam.IPAMReq{IP: &ipv4}); err != nil {
					log.Warningf("error while releasing IPv4 %s: %s", ep.IPv4.IP(), err)
				}
			}
			ipv6 := ep.IPv6.IP()
			if err := d.ReleaseIP(ipamType, ipam.IPAMReq{IP: &ipv6}); err != nil {
				log.Warningf("error while releasing IPv6 %s: %s", ep.IPv6.IP(), err)
			}
		}
	}
	d.containersMU.Unlock()
}
