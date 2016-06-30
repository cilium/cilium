package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	dTypes "github.com/docker/engine-api/types"
	dTypesEvents "github.com/docker/engine-api/types/events"
	k8sAPI "k8s.io/kubernetes/pkg/api"
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

const (
	syncRateDocker = time.Duration(30 * time.Second)
)

// EnableDockerEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func (d *Daemon) EnableDockerEventListener() error {
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(time.Now().Unix(), 10)}
	r, err := d.dockerClient.Events(eo)
	if err != nil {
		return err
	}

	d.EnableDockerSync(true)

	log.Debugf("Listening for docker events")
	go d.listenForEvents(r)
	return nil
}

func (d *Daemon) EnableDockerSync(once bool) {
	for {
		cList, err := d.dockerClient.ContainerList(dTypes.ContainerListOptions{All: false})
		if err != nil {
			log.Error("Failed to retrieve the container list %s", err)
		}
		for _, cont := range cList {
			go d.createContainer(cont.ID, cont.Labels)
		}

		if once {
			return
		}
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
			d.createContainer(m.ID, m.Actor.Attributes)
		case "die":
			d.deleteContainer(m.ID)
		}
	}
}

func getCiliumEndpointID(cont dTypes.ContainerJSON, gwIP net.IP) string {
	for _, contNetwork := range cont.NetworkSettings.Networks {
		ipv6gw := net.ParseIP(contNetwork.IPv6Gateway)
		if ipv6gw.Equal(gwIP) {
			ip := net.ParseIP(contNetwork.GlobalIPv6Address)
			id := common.EndpointAddr2ID(ip)
			return strconv.FormatUint(uint64(id), 10)
		}
	}
	return ""
}

func (d *Daemon) fetchK8sLabels(dockerLbls map[string]string) (map[string]string, error) {
	ns := k8sDockerLbls.GetPodNamespace(dockerLbls)
	if ns == "" {
		ns = "default"
	}
	podName := k8sDockerLbls.GetPodName(dockerLbls)
	if podName == "" {
		return nil, nil
	}
	result := &k8sAPI.Pod{}
	log.Debugf("Connecting to kubernetes to retrieve labels for pod %s ns %s", podName, ns)
	if err := d.k8sClient.Get().Namespace(ns).Resource("pods").Name(podName).Do().Into(result); err != nil {
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

	d.validLabelPrefixesMU.Lock()
	defer d.validLabelPrefixesMU.Unlock()
	return d.conf.ValidLabelPrefixes.FilterLabels(ciliumLabels)
}

func (d *Daemon) createContainer(dockerID string, allLabels map[string]string) {
	log.Debugf("Processing container %s", dockerID)

	ciliumLabels := d.getFilteredLabels(allLabels)

	if err := d.refreshContainerLabels(dockerID, ciliumLabels, true); err != nil {
		log.Errorf("%s", err)
	}
}

func (d *Daemon) refreshContainerLabels(dockerID string, labels types.Labels, root bool) error {
	if isNewContainer, container, err := d.updateOperationalLabels(dockerID, labels, root); err != nil {
		return err
	} else {
		return d.updateContainer(container, isNewContainer)
	}
}

func (d *Daemon) updateOperationalLabels(dockerID string, newLabels types.Labels, root bool) (bool, *types.Container, error) {
	dockerCont, err := d.dockerClient.ContainerInspect(dockerID)
	if err != nil {
		return false, nil, fmt.Errorf("Error while inspecting container '%s': %s", dockerID, err)
	}

	isNewContainer := false
	d.containersMU.Lock()

	var cont types.Container

	if ciliumContainer, ok := d.containers[dockerID]; !ok {
		isNewContainer = true
		opLabels := types.OpLabels{
			AllLabels:      newLabels.DeepCopy(),
			CiliumLabels:   newLabels.DeepCopy(),
			EndpointLabels: newLabels.DeepCopy(),
		}
		cont = types.Container{dockerCont, opLabels}
	} else {
		if root {
			// Clean all labels that are deleted and not present in root labels
			deletedLabels := ciliumContainer.OpLabels.GetDeletedLabels()
			for k, _ := range newLabels {
				delete(deletedLabels, k)
			}
			for k, v := range deletedLabels {
				log.Infof("Purging deleted endpoint label %s from container %s", v, ciliumContainer.ID)
				delete(ciliumContainer.OpLabels.AllLabels, k)
			}
		}

		allLabelsSHA256, err := ciliumContainer.OpLabels.AllLabels.SHA256Sum()
		if err != nil {
			log.Errorf("Error calculating SHA256Sum of labels %+v: %s", ciliumContainer.OpLabels.AllLabels, err)
		}

		allLabelsCpy := ciliumContainer.OpLabels.AllLabels.DeepCopy()
		allLabelsCpy.MergeLabels(newLabels)

		newLabelsSHA256, err := allLabelsCpy.SHA256Sum()
		if err != nil {
			log.Errorf("Error calculating SHA256Sum of labels %+v: %s", allLabelsCpy, err)
		}

		// Someone has changed labels so we need to update this everywhere
		if allLabelsSHA256 != newLabelsSHA256 {
			isNewContainer = true
			ciliumContainer.OpLabels.AllLabels.MergeLabels(newLabels)
			ciliumContainer.OpLabels.CiliumLabels.MergeLabels(newLabels)
			if err := d.DeleteLabelsBySHA256(allLabelsSHA256, dockerID); err != nil {
				log.Errorf("Error while deleting old labels (%+v) of container %s: %s", allLabelsSHA256, dockerID, err)
			}
		} else {
			epLabelsSHA256, err := ciliumContainer.OpLabels.EndpointLabels.SHA256Sum()
			if err != nil {
				log.Errorf("Error calculating SHA256Sum of labels %+v: %s", ciliumContainer.OpLabels.EndpointLabels, err)
			}

			newLabelsSHA256, err := newLabels.SHA256Sum()
			if err != nil {
				log.Errorf("Error calculating SHA256Sum of labels %+v: %s", newLabels, err)
			}

			if epLabelsSHA256 != newLabelsSHA256 {
				isNewContainer = true
				ciliumContainer.OpLabels.EndpointLabels = newLabels
			}
		}

		cont = types.Container{dockerCont, ciliumContainer.OpLabels}
	}

	d.containers[dockerID] = &cont
	contCpy := cont

	d.containersMU.Unlock()

	return isNewContainer, &contCpy, nil
}

func (d *Daemon) updateContainer(container *types.Container, isNewContainer bool) error {
	dockerID := container.ID

	log.Debugf("Putting labels %+v", container.OpLabels.EndpointLabels)
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
	for try < maxTries {
		if ep = d.setEndpointSecLabel(ciliumID, dockerID, dockerEPID, secCtxlabels); ep != nil {
			break
		}
		if container.IsDockerAndInfracontainer() {
			log.Warningf("Something went wrong, the docker ID '%s' was not locally found. Attempt... %d", dockerID, try)
		}
		time.Sleep(time.Duration(try) * time.Second)
		try++
	}
	if try >= maxTries {
		if container.IsDockerAndInfracontainer() {
			return fmt.Errorf("It was impossible to store the SecLabel %d for docker endpoint ID '%s'", secCtxlabels.ID, dockerID)
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

	log.Infof("Added SecLabelID %d to container %s", secCtxlabels.ID, dockerID)

	return nil
}

func (d *Daemon) deleteContainer(dockerID string) {
	log.Debugf("Processing container %s", dockerID)

	d.containersMU.Lock()
	if container, ok := d.containers[dockerID]; ok {
		d.endpointsMU.Lock()
		ep := d.lookupDockerID(dockerID)
		d.endpointsMU.Unlock()

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
		}
	}
	d.containersMU.Unlock()
}
