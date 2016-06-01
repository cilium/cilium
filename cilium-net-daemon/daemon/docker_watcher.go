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
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/dockertools"
)

// EnableDockerEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func (d *Daemon) EnableDockerEventListener() error {
	eo := dTypes.EventsOptions{Since: strconv.FormatInt(time.Now().Unix(), 10)}
	r, err := d.dockerClient.Events(eo)
	if err != nil {
		return err
	}
	log.Debugf("Listening for docker events")
	go d.listenForEvents(r)
	return nil
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
			d.createContainer(m)
		case "die":
			d.deleteContainer(m)
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

func (d *Daemon) createContainer(m dTypesEvents.Message) {
	dockerID := m.Actor.ID
	log.Debugf("Processing container %s", dockerID)
	allLabels := m.Actor.Attributes
	cont, err := d.dockerClient.ContainerInspect(dockerID)
	if err != nil {
		log.Errorf("Error while inspecting container '%s': %s", dockerID, err)
		return
	}

	ciliumLabels := d.getFilteredLabels(allLabels)

	secCtxlabels, isNew, err := d.PutLabels(ciliumLabels)
	if err != nil {
		log.Errorf("Error while getting labels ID: %s", err)
		return
	}
	defer func() {
		if err != nil {
			log.Infof("Deleting label ID %d because of failure.", secCtxlabels.ID)
			d.DeleteLabelsByUUID(secCtxlabels.ID)
		}
	}()

	ciliumID := getCiliumEndpointID(cont, d.conf.NodeAddress)
	var dockerEPID string
	if cont.NetworkSettings != nil {
		dockerEPID = cont.NetworkSettings.EndpointID
	}

	try := 1
	maxTries := 5
	var ep *types.Endpoint
	for try < maxTries {
		if ep = d.setEndpointSecLabel(ciliumID, dockerID, dockerEPID, secCtxlabels); ep != nil {
			break
		}
		log.Warningf("Something went wrong, the docker ID '%s' was not locally found. Attempt... %d", dockerID, try)
		time.Sleep(time.Duration(try) * time.Second)
		try++
	}
	if try >= maxTries {
		err = fmt.Errorf("It was impossible to store the SecLabel %d for docker endpoint ID '%s'", secCtxlabels.ID, dockerID)
		log.Error(err)
		return
	}
	if err = d.createBPFMAPs(ep.ID); err != nil {
		err = fmt.Errorf("Unable to create & attach BPF programs for container %s: %s", dockerID, err)
		log.Error(err)
		return
	}

	// Perform the policy map updates after programs have been created
	if isNew {
		d.triggerPolicyUpdates([]uint32{secCtxlabels.ID})
	}

	log.Infof("Added SecLabelID %d to container %s", secCtxlabels.ID, dockerID)
}

func (d *Daemon) deleteContainer(m dTypesEvents.Message) {
	dockerID := m.Actor.ID
	log.Debugf("Processing container %s", dockerID)
	allLabels := m.Actor.Attributes

	ciliumLabels := d.getFilteredLabels(allLabels)

	sha256sum, err := ciliumLabels.SHA256Sum()
	if err != nil {
		log.Errorf("Error while creating SHA256Sum for labels %+v: %s", ciliumLabels, err)
	}

	if err := d.DeleteLabelsBySHA256(sha256sum); err != nil {
		log.Errorf("Error while deleting labels (SHA256SUM:%s) %+v: %s", sha256sum, ciliumLabels, err)
	}
}
